"""
Тесты для Блока 3: Хранение данных

Проверяет:
- Наличие индексов в PostgreSQL
- Корректность SQL-запросов
- Создание Parquet-файла
"""

import os
import pytest
import psycopg2
import duckdb

# Параметры подключения (можно переопределить через переменные окружения)
PG_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "database": os.getenv("DB_NAME", "security_logs"),
    "user": os.getenv("DB_USER", "analyst"),
    "password": os.getenv("DB_PASSWORD", "security123"),
}

LESSON_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PARQUET_PATH = os.path.join(LESSON_DIR, "lesson03", "data", "auth_events.parquet")


@pytest.fixture
def pg_connection():
    """Создаёт подключение к PostgreSQL."""
    try:
        conn = psycopg2.connect(**PG_CONFIG)
        yield conn
        conn.close()
    except psycopg2.OperationalError as e:
        pytest.skip(f"PostgreSQL недоступен: {e}")


@pytest.fixture
def pg_cursor(pg_connection):
    """Создаёт курсор PostgreSQL."""
    cursor = pg_connection.cursor()
    yield cursor
    cursor.close()


class TestPostgreSQLIndexes:
    """Тесты на наличие индексов."""

    def test_timestamp_index_exists(self, pg_cursor):
        """Проверяет наличие индекса по timestamp."""
        pg_cursor.execute("""
            SELECT indexname FROM pg_indexes
            WHERE tablename = 'auth_events' 
              AND indexdef LIKE '%timestamp%'
        """)
        indexes = [row[0] for row in pg_cursor.fetchall()]
        assert len(indexes) > 0, "Отсутствует индекс по полю timestamp"

    def test_source_ip_index_exists(self, pg_cursor):
        """Проверяет наличие индекса по source_ip."""
        pg_cursor.execute("""
            SELECT indexname FROM pg_indexes
            WHERE tablename = 'auth_events' 
              AND indexdef LIKE '%source_ip%'
        """)
        indexes = [row[0] for row in pg_cursor.fetchall()]
        assert len(indexes) > 0, "Отсутствует индекс по полю source_ip"

    def test_success_index_exists(self, pg_cursor):
        """Проверяет наличие индекса по success."""
        pg_cursor.execute("""
            SELECT indexname FROM pg_indexes
            WHERE tablename = 'auth_events' 
              AND indexdef LIKE '%success%'
        """)
        indexes = [row[0] for row in pg_cursor.fetchall()]
        assert len(indexes) > 0, "Отсутствует индекс по полю success"


class TestPostgreSQLQueries:
    """Тесты на корректность SQL-запросов."""

    def test_top_failed_ips_query(self, pg_cursor):
        """Проверяет запрос TOP-10 IP по неудачным входам."""
        pg_cursor.execute("""
            SELECT source_ip, COUNT(*) as failed_count
            FROM auth_events
            WHERE success = false
            GROUP BY source_ip
            ORDER BY failed_count DESC
            LIMIT 10
        """)
        results = pg_cursor.fetchall()
        # Запрос должен выполниться без ошибок
        assert isinstance(results, list)

    def test_hourly_distribution_query(self, pg_cursor):
        """Проверяет запрос распределения по часам."""
        pg_cursor.execute("""
            SELECT EXTRACT(HOUR FROM timestamp) as hour, COUNT(*) as event_count
            FROM auth_events
            GROUP BY EXTRACT(HOUR FROM timestamp)
            ORDER BY hour
        """)
        results = pg_cursor.fetchall()
        assert isinstance(results, list)
        # Часов не больше 24
        assert len(results) <= 24

    def test_brute_force_detection_query(self, pg_cursor):
        """Проверяет запрос обнаружения brute-force."""
        pg_cursor.execute("""
            WITH user_attempts AS (
                SELECT 
                    username,
                    source_ip,
                    timestamp,
                    success,
                    LAG(success) OVER (
                        PARTITION BY username, source_ip 
                        ORDER BY timestamp
                    ) as prev_success
                FROM auth_events
            )
            SELECT username, source_ip, COUNT(*) as suspicious_count
            FROM user_attempts
            WHERE success = true AND prev_success = false
            GROUP BY username, source_ip
            HAVING COUNT(*) >= 1
            ORDER BY suspicious_count DESC
            LIMIT 10
        """)
        results = pg_cursor.fetchall()
        assert isinstance(results, list)


class TestDuckDBParquet:
    """Тесты для DuckDB и Parquet."""

    def test_parquet_file_exists(self):
        """Проверяет наличие Parquet-файла."""
        assert os.path.exists(PARQUET_PATH), \
            f"Parquet-файл не найден: {PARQUET_PATH}"

    def test_parquet_readable(self):
        """Проверяет, что Parquet-файл читается DuckDB."""
        if not os.path.exists(PARQUET_PATH):
            pytest.skip("Parquet-файл не создан")
        
        result = duckdb.sql(f"SELECT COUNT(*) FROM '{PARQUET_PATH}'").fetchone()
        assert result[0] > 0, "Parquet-файл пустой"  # pyright: ignore[reportOptionalSubscript]

    def test_parquet_schema(self):
        """Проверяет схему Parquet-файла."""
        if not os.path.exists(PARQUET_PATH):
            pytest.skip("Parquet-файл не создан")
        
        result = duckdb.sql(f"""
            SELECT column_name 
            FROM parquet_schema('{PARQUET_PATH}')
        """).fetchall()
        columns = [row[0] for row in result]
        
        required_columns = ['timestamp', 'event_type', 'username', 'source_ip', 'success']
        for col in required_columns:
            assert col in columns, f"Отсутствует колонка {col} в Parquet"

    def test_duckdb_query_on_parquet(self):
        """Проверяет выполнение запроса по Parquet."""
        if not os.path.exists(PARQUET_PATH):
            pytest.skip("Parquet-файл не создан")
        
        result = duckdb.sql(f"""
            FROM '{PARQUET_PATH}'
            SELECT source_ip, COUNT(*) as cnt
            WHERE success = false
            GROUP BY ALL
            ORDER BY cnt DESC
            LIMIT 5
        """).fetchall()
        
        assert isinstance(result, list)
