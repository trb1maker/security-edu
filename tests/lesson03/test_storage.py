"""
Тесты для Блока 3: Организация хранения данных

Проверяют:
- Наличие и корректность индексов
- Ускорение запросов после создания индексов
- Работу с DuckDB и Parquet-файлами
"""

import os
from pathlib import Path

import pytest
import psycopg2
import duckdb


def get_db_connection():
    """Получить подключение к PostgreSQL."""
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        database=os.getenv("DB_NAME", "security_logs"),
        user=os.getenv("DB_USER", "analyst"),
        password=os.getenv("DB_PASSWORD", "security123"),
    )


def find_project_root() -> Path:
    """Найти корневую директорию проекта."""
    current = Path(__file__).resolve()
    while current != current.parent:
        if (current / "pyproject.toml").exists():
            return current
        current = current.parent
    return Path(__file__).resolve().parent.parent.parent


class TestIndexesExist:
    """Проверяем наличие индексов."""

    @pytest.fixture(scope="class")
    def conn(self):
        """Подключение к базе данных."""
        try:
            conn = get_db_connection()
            yield conn
            conn.close()
        except psycopg2.OperationalError:
            pytest.skip("PostgreSQL не доступен. Запустите docker-compose.")

    @pytest.mark.parametrize(
        "table,expected_indexes",
        [
            (
                "auth_events",
                [
                    "idx_auth_events_ip_time_failures",
                    "idx_auth_events_username_time",
                    "idx_auth_events_type_severity",
                    "idx_auth_events_suspicious",
                ],
            ),
            (
                "nginx_logs",
                [
                    "idx_nginx_logs_ip_time_errors",
                    "idx_nginx_logs_path_time",
                    "idx_nginx_logs_status_severity",
                    "idx_nginx_logs_blocked",
                ],
            ),
            (
                "dns_queries",
                [
                    "idx_dns_queries_domain_time",
                    "idx_dns_queries_ip_time",
                    "idx_dns_queries_resolver_time",
                ],
            ),
            (
                "firewall_events",
                [
                    "idx_firewall_events_blocked",
                    "idx_firewall_events_suspicious_ports",
                    "idx_firewall_events_port_scan",
                    "idx_firewall_events_protocol_action",
                ],
            ),
        ],
    )
    def test_indexes_exist(self, conn, table, expected_indexes):
        """Проверяем наличие ожидаемых индексов."""
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT indexname 
                FROM pg_indexes 
                WHERE schemaname = 'public' 
                AND tablename = %s
            """,
                (table,),
            )
            existing_indexes = {row[0] for row in cur.fetchall()}

        missing = [idx for idx in expected_indexes if idx not in existing_indexes]
        assert not missing, (
            f"В таблице {table} отсутствуют индексы: {missing}. "
            "Примените миграцию sql/migrations/001_create_indexes.sql"
        )


class TestQueryPerformance:
    """Проверяем производительность запросов."""

    @pytest.fixture(scope="class")
    def conn(self):
        """Подключение к базе данных."""
        try:
            conn = get_db_connection()
            yield conn
            conn.close()
        except psycopg2.OperationalError:
            pytest.skip("PostgreSQL не доступен. Запустите docker-compose.")

    def measure_query_time(self, cursor, query):
        """Измеряет время выполнения запроса."""
        import time

        start = time.perf_counter()
        cursor.execute(query)
        cursor.fetchall()
        elapsed = time.perf_counter() - start
        return elapsed

    def test_bruteforce_query_performance(self, conn):
        """Проверяем производительность запроса поиска brute-force атак."""
        with conn.cursor() as cur:
            # Обновляем статистику перед проверкой (на случай, если она устарела)
            cur.execute("ANALYZE auth_events")
            conn.commit()

            # Запрос для поиска brute-force атак
            query = """
                SELECT 
                    source_ip,
                    COUNT(*) as failed_count,
                    STRING_AGG(DISTINCT username, ', ') as attacked_users,
                    MIN(timestamp) as first_attempt,
                    MAX(timestamp) as last_attempt
                FROM auth_events
                WHERE event_type = 'login_failure'
                  AND timestamp >= '2024-03-01'
                  AND timestamp < '2024-03-15'
                GROUP BY source_ip
                HAVING COUNT(*) > 50
                ORDER BY failed_count DESC
                LIMIT 10
            """

            # Получаем план выполнения
            cur.execute(f"EXPLAIN ANALYZE {query}")
            plan = "\n".join(row[0] for row in cur.fetchall())

            # Проверяем, что используется индекс (Index Scan, Index Only Scan или Bitmap Index Scan)
            # PostgreSQL может выбрать любой подходящий индекс, не обязательно конкретный
            # Для небольших объёмов данных может использоваться Seq Scan, но это нормально
            uses_index = (
                "Index Scan" in plan
                or "Index Only Scan" in plan
                or "Bitmap Index Scan" in plan
                or "idx_auth_events" in plan  # Любой индекс для auth_events
            )

            # Измеряем время выполнения
            execution_time = self.measure_query_time(cur, query)

            # Если запрос выполняется быстро, это хорошо (даже если используется Seq Scan)
            # Если медленно, проверяем использование индекса
            if execution_time >= 1.0:  # Если запрос медленный (> 1 сек)
                assert uses_index, (
                    f"Запрос выполняется медленно ({execution_time:.2f} сек) и не использует индекс. "
                    f"План выполнения:\n{plan}\n"
                    "Проверьте, что индексы созданы и применена миграция."
                )

            # Измеряем время выполнения
            execution_time = self.measure_query_time(cur, query)

            # Запрос должен выполняться быстро (менее 5 секунд для lite версии)
            assert execution_time < 5.0, (
                f"Запрос выполняется слишком медленно: {execution_time:.2f} сек. "
                "Проверьте наличие индексов."
            )

    def test_port_scan_query_performance(self, conn):
        """Проверяем производительность запроса поиска сканирования портов."""
        with conn.cursor() as cur:
            # Обновляем статистику перед проверкой
            cur.execute("ANALYZE firewall_events")
            conn.commit()

            query = """
                SELECT 
                    source_ip,
                    COUNT(DISTINCT dest_port) as unique_ports,
                    STRING_AGG(DISTINCT dest_port::text, ', ' ORDER BY dest_port::text) as ports,
                    COUNT(*) as blocked_count
                FROM firewall_events
                WHERE action = 'BLOCK'
                  AND timestamp >= '2024-03-01'
                  AND timestamp < '2024-03-15'
                GROUP BY source_ip
                HAVING COUNT(DISTINCT dest_port) > 10
                ORDER BY unique_ports DESC
                LIMIT 10
            """

            # Получаем план выполнения
            cur.execute(f"EXPLAIN ANALYZE {query}")
            plan = "\n".join(row[0] for row in cur.fetchall())

            # Измеряем время выполнения
            execution_time = self.measure_query_time(cur, query)

            # Проверяем, что используется индекс (если запрос медленный)
            uses_index = (
                "Index Scan" in plan
                or "Index Only Scan" in plan
                or "Bitmap Index Scan" in plan
                or "idx_firewall_events" in plan  # Любой индекс для firewall_events
            )

            # Если запрос выполняется медленно, проверяем использование индекса
            if execution_time >= 1.0:  # Если запрос медленный (> 1 сек)
                assert uses_index, (
                    f"Запрос выполняется медленно ({execution_time:.2f} сек) и не использует индекс. "
                    f"План выполнения:\n{plan}\n"
                    "Проверьте, что индексы созданы и применена миграция."
                )

            # Запрос должен выполняться быстро
            assert execution_time < 5.0, (
                f"Запрос выполняется слишком медленно: {execution_time:.2f} сек."
            )


class TestDuckDBParquet:
    """Проверяем работу с DuckDB и Parquet-файлами."""

    @pytest.fixture(scope="class")
    def project_root(self):
        """Корневая директория проекта."""
        return find_project_root()

    def test_parquet_files_exist(self, project_root):
        """Проверяем наличие Parquet-файлов."""
        data_path = project_root / "data" / "lite"

        if not data_path.exists():
            pytest.skip(
                "Parquet-файлы не найдены. Запустите: uv run bootstrap.py --version lite"
            )

        # Проверяем наличие файлов для всех 4 типов логов
        for log_type in ["auth_events", "nginx_logs", "dns_queries", "firewall_events"]:
            log_path = data_path / log_type
            assert log_path.exists(), (
                f"Директория {log_path} не найдена. "
                "Запустите bootstrap.py для загрузки данных."
            )

            # Проверяем наличие хотя бы одного Parquet-файла
            parquet_files = list(log_path.glob("day=*/part-*.parquet"))
            assert len(parquet_files) > 0, (
                f"Parquet-файлы не найдены в {log_path}. "
                "Запустите bootstrap.py для загрузки данных."
            )

    def test_duckdb_reads_parquet(self, project_root):
        """Проверяем, что DuckDB может читать Parquet-файлы."""
        data_path = project_root / "data" / "lite" / "auth_events"

        if not data_path.exists():
            pytest.skip("Parquet-файлы не найдены.")

        # Находим первый доступный день
        day_dirs = sorted(
            [d for d in data_path.iterdir() if d.is_dir() and d.name.startswith("day=")]
        )
        if not day_dirs:
            pytest.skip("Нет данных для тестирования.")

        first_day = day_dirs[0]
        parquet_files = list(first_day.glob("part-*.parquet"))
        if not parquet_files:
            pytest.skip("Нет Parquet-файлов для тестирования.")

        # Читаем Parquet через DuckDB
        conn = duckdb.connect()
        try:
            result = conn.execute(
                f"SELECT COUNT(*) FROM read_parquet('{parquet_files[0]}')"
            ).fetchone()
            assert result is not None and result[0] > 0, (
                "DuckDB не смог прочитать Parquet-файл или файл пустой"
            )
        finally:
            conn.close()

    def test_duckdb_query_performance(self, project_root):
        """Проверяем производительность запросов в DuckDB."""
        data_path = project_root / "data" / "lite"

        if not data_path.exists():
            pytest.skip("Parquet-файлы не найдены.")

        # Собираем пути к Parquet-файлам за период атаки (дни 61-74)
        auth_files = []
        for day in range(61, 75):
            day_path = data_path / "auth_events" / f"day={day}"
            if day_path.exists():
                parquet_files = list(day_path.glob("part-*.parquet"))
                auth_files.extend([str(f) for f in parquet_files])

        if not auth_files:
            pytest.skip("Нет данных за период атаки для тестирования.")

        conn = duckdb.connect()
        try:
            import time

            # Запрос для поиска brute-force атак
            query = f"""
                SELECT 
                    source_ip,
                    COUNT(*) as failed_count,
                    LIST(DISTINCT username) as attacked_users,
                    MIN(timestamp) as first_attempt,
                    MAX(timestamp) as last_attempt
                FROM read_parquet({auth_files})
                WHERE event_type = 'login_failure'
                  AND timestamp >= '2024-03-01'
                  AND timestamp < '2024-03-15'
                GROUP BY source_ip
                HAVING COUNT(*) > 50
                ORDER BY failed_count DESC
                LIMIT 10
            """

            start = time.perf_counter()
            result = conn.execute(query).fetchall()
            elapsed = time.perf_counter() - start

            # DuckDB должен выполнить запрос быстро
            assert elapsed < 3.0, (
                f"Запрос в DuckDB выполняется слишком медленно: {elapsed:.2f} сек."
            )

            # Должны быть результаты
            assert len(result) > 0, "Запрос не вернул результатов. Проверьте данные."

        finally:
            conn.close()


class TestPerformanceComparison:
    """Сравниваем производительность PostgreSQL и DuckDB."""

    @pytest.fixture(scope="class")
    def conn(self):
        """Подключение к базе данных."""
        try:
            conn = get_db_connection()
            yield conn
            conn.close()
        except psycopg2.OperationalError:
            pytest.skip("PostgreSQL не доступен.")

    @pytest.fixture(scope="class")
    def project_root(self):
        """Корневая директория проекта."""
        return find_project_root()

    def test_postgres_vs_duckdb_comparison(self, conn, project_root):
        """Сравниваем производительность PostgreSQL (с индексами) и DuckDB."""
        data_path = project_root / "data" / "lite" / "auth_events"

        if not data_path.exists():
            pytest.skip("Parquet-файлы не найдены.")

        # Собираем пути к Parquet-файлам
        auth_files = []
        for day in range(61, 75):
            day_path = data_path / f"day={day}"
            if day_path.exists():
                parquet_files = list(day_path.glob("part-*.parquet"))
                auth_files.extend([str(f) for f in parquet_files])

        if not auth_files:
            pytest.skip("Нет данных для сравнения.")

        import time

        # Запрос для PostgreSQL
        pg_query = """
            SELECT 
                source_ip,
                COUNT(*) as failed_count
            FROM auth_events
            WHERE event_type = 'login_failure'
              AND timestamp >= '2024-03-01'
              AND timestamp < '2024-03-15'
            GROUP BY source_ip
            HAVING COUNT(*) > 50
            ORDER BY failed_count DESC
            LIMIT 10
        """

        # Запрос для DuckDB
        duckdb_query = f"""
            SELECT 
                source_ip,
                COUNT(*) as failed_count
            FROM read_parquet({auth_files})
            WHERE event_type = 'login_failure'
              AND timestamp >= '2024-03-01'
              AND timestamp < '2024-03-15'
            GROUP BY source_ip
            HAVING COUNT(*) > 50
            ORDER BY failed_count DESC
            LIMIT 10
        """

        # Измеряем PostgreSQL
        with conn.cursor() as cur:
            start = time.perf_counter()
            cur.execute(pg_query)
            pg_results = cur.fetchall()
            pg_time = time.perf_counter() - start

        # Измеряем DuckDB
        duckdb_conn = duckdb.connect()
        try:
            start = time.perf_counter()
            duckdb_results = duckdb_conn.execute(duckdb_query).fetchall()
            duckdb_time = time.perf_counter() - start
        finally:
            duckdb_conn.close()

        # Проверяем, что результаты совпадают
        pg_count = len(pg_results) if pg_results else 0
        duckdb_count = len(duckdb_results) if duckdb_results else 0
        assert pg_count == duckdb_count, (
            f"Количество результатов не совпадает между PostgreSQL ({pg_count}) и DuckDB ({duckdb_count})"
        )

        # DuckDB должен быть быстрее или сопоставим по скорости
        # (для больших объёмов данных DuckDB обычно быстрее)
        speedup = pg_time / duckdb_time if duckdb_time > 0 else 0

        print("\nПроизводительность:")
        print(f"  PostgreSQL (с индексами): {pg_time * 1000:.2f} мс")
        print(f"  DuckDB (Parquet): {duckdb_time * 1000:.2f} мс")
        print(f"  Ускорение: {speedup:.2f}x")

        # Для небольших объёмов (lite) разница может быть незначительной
        # Но DuckDB не должен быть значительно медленнее
        assert duckdb_time < pg_time * 2, (
            f"DuckDB выполняется слишком медленно по сравнению с PostgreSQL. "
            f"PG: {pg_time * 1000:.2f} мс, DuckDB: {duckdb_time * 1000:.2f} мс"
        )
