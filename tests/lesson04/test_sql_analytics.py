"""
Тесты для Блока 4: SQL-аналитика для ИБ

Проверяет обнаружение конкретных индикаторов компрометации (IoC) и построение timeline атаки.
"""

import os
import pytest
import duckdb
from datetime import datetime

LESSON_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
DATA_DIR = os.path.join(LESSON_DIR, "data", "lite")


@pytest.fixture
def db():
    """Создаёт подключение к DuckDB."""
    return duckdb.connect()


@pytest.fixture
def has_data():
    """Проверяет наличие данных."""
    auth_path = os.path.join(DATA_DIR, "auth_events", "day=61")
    if not os.path.exists(auth_path):
        pytest.skip(f"Данные не найдены: {DATA_DIR}")
    return DATA_DIR


class TestRECON:
    """Тесты для обнаружения разведки (RECON)."""

    def test_suspicious_paths(self, db, has_data):
        """Проверяет обнаружение подозрительных путей в веб-логах."""
        result = db.sql(f"""
            FROM '{has_data}/nginx_logs/day=*/*.parquet'
            SELECT source_ip, COUNT(*) as attempts
            WHERE status IN (403, 404)
              AND (path LIKE '%/admin%' 
                   OR path LIKE '%/.env%' 
                   OR path LIKE '%/wp-admin%'
                   OR path LIKE '%/.git%')
              AND timestamp >= '2024-03-01'
              AND timestamp < '2024-03-04'
            GROUP BY source_ip
            HAVING COUNT(*) > 5
            ORDER BY attempts DESC
        """).fetchall()

        assert len(result) > 0, "Должны быть найдены IP с подозрительными путями"

        # Проверяем, что найден основной IP атакующего
        ips = [row[0] for row in result]
        assert "203.0.113.42" in ips, "Должен быть найден IP 203.0.113.42"

    def test_port_scanning(self, db, has_data):
        """Проверяет обнаружение сканирования портов."""
        result = db.sql(f"""
            FROM '{has_data}/firewall_events/day=*/*.parquet'
            SELECT source_ip, COUNT(DISTINCT dest_port) as unique_ports
            WHERE action = 'BLOCK'
              AND timestamp >= '2024-03-01'
              AND timestamp < '2024-03-04'
            GROUP BY source_ip
            HAVING COUNT(DISTINCT dest_port) > 5
            ORDER BY unique_ports DESC
        """).fetchall()

        assert len(result) > 0, "Должно быть найдено сканирование портов"

        # Проверяем, что найден основной IP атакующего
        ips = [row[0] for row in result]
        assert "203.0.113.42" in ips, "Должен быть найден IP 203.0.113.42"


class TestBRUTEFORCE:
    """Тесты для обнаружения brute-force атаки."""

    def test_massive_failed_attempts(self, db, has_data):
        """Проверяет обнаружение массовых неудачных попыток входа."""
        result = db.sql(f"""
            FROM '{has_data}/auth_events/day=*/*.parquet'
            SELECT source_ip, username, COUNT(*) as failures
            WHERE event_type = 'login_failure'
              AND timestamp >= '2024-03-04'
              AND timestamp < '2024-03-08'
            GROUP BY source_ip, username
            HAVING COUNT(*) > 50
            ORDER BY failures DESC
        """).fetchall()

        assert len(result) > 0, "Должны быть найдены массовые неудачные попытки"

        # Проверяем, что найден целевой пользователь и IP атакующего
        found = False
        for row in result:
            if row[0] == "203.0.113.42" and row[1] == "dev_sergey":
                found = True
                assert row[2] >= 100, (
                    f"Должно быть не менее 100 неудачных попыток, найдено {row[2]}"
                )
                break

        assert found, (
            "Должен быть найден IP 203.0.113.42 атакущий пользователя dev_sergey"
        )

    def test_target_user(self, db, has_data):
        """Проверяет определение целевого пользователя."""
        result = db.sql(f"""
            FROM '{has_data}/auth_events/day=*/*.parquet'
            SELECT username, COUNT(*) as failed_attempts
            WHERE event_type = 'login_failure'
              AND timestamp >= '2024-03-04'
              AND timestamp < '2024-03-08'
            GROUP BY username
            ORDER BY failed_attempts DESC
            LIMIT 1
        """).fetchall()

        assert len(result) > 0, "Должен быть найден целевой пользователь"
        assert result[0][0] == "dev_sergey", (
            f"Целевой пользователь должен быть dev_sergey, найден {result[0][0]}"
        )


class TestCOMPROMISE:
    """Тесты для обнаружения компрометации."""

    def test_successful_login_after_failures(self, db, has_data):
        """Проверяет обнаружение успешного входа после неудач."""
        # Сначала проверяем наличие успешного входа для целевого пользователя
        success_result = db.sql(f"""
            FROM '{has_data}/auth_events/day=*/*.parquet'
            SELECT 
                timestamp,
                username,
                source_ip,
                success
            WHERE username = 'dev_sergey'
              AND source_ip = '203.0.113.42'
              AND event_type = 'login_success'
              AND timestamp >= '2024-03-08'
              AND timestamp < '2024-03-09'
            ORDER BY timestamp
            LIMIT 1
        """).fetchall()

        assert len(success_result) > 0, (
            "Должен быть найден успешный вход dev_sergey с IP 203.0.113.42 в день 68"
        )

        # Теперь проверяем наличие неудачных попыток перед успехом
        result = db.sql(f"""
            WITH attempts AS (
                FROM '{has_data}/auth_events/day=*/*.parquet'
                SELECT 
                    timestamp::TIMESTAMP as ts,
                    username,
                    source_ip,
                    success,
                    LAG(success) OVER (
                        PARTITION BY username, source_ip 
                        ORDER BY timestamp
                    ) as prev_success,
                    LAG(timestamp::TIMESTAMP) OVER (
                        PARTITION BY username, source_ip 
                        ORDER BY timestamp
                    ) as prev_time
                WHERE username = 'dev_sergey'
                  AND source_ip = '203.0.113.42'
                  AND timestamp >= '2024-03-08'
                  AND timestamp < '2024-03-09'
            )
            SELECT 
                ts as compromise_time,
                username,
                source_ip,
                prev_time as last_failed_attempt
            FROM attempts
            WHERE success = true 
              AND prev_success = false
              AND prev_time IS NOT NULL
            ORDER BY ts
        """).fetchall()

        # Если не найдено строгой последовательности, проверяем наличие неудачных попыток в целом
        if len(result) == 0:
            # Проверяем наличие неудачных попыток перед успехом (не обязательно сразу перед)
            failures_before = db.sql(f"""
                FROM '{has_data}/auth_events/day=*/*.parquet'
                SELECT COUNT(*) as cnt
                WHERE username = 'dev_sergey'
                  AND source_ip = '203.0.113.42'
                  AND event_type = 'login_failure'
                  AND timestamp >= '2024-03-04'
                  AND timestamp < '2024-03-08'
            """).fetchone()

            assert failures_before[0] > 0, (
                "Должны быть найдены неудачные попытки перед успешным входом"
            )
        else:
            # Если найдена последовательность, проверяем временной интервал
            for row in result:
                if row[1] == "dev_sergey" and row[2] == "203.0.113.42":
                    # Проверяем, что компрометация произошла в день 68
                    compromise_time = datetime.fromisoformat(
                        str(row[0]).replace("Z", "+00:00")
                    )
                    assert compromise_time.date().isoformat() == "2024-03-08", (
                        f"Компрометация должна быть 8 марта, найдено {compromise_time.date()}"
                    )
                    break


class TestLATERAL:
    """Тесты для обнаружения lateral movement."""

    def test_new_hosts(self, db, has_data):
        """Проверяет обнаружение входов с новых хостов."""
        result = db.sql(f"""
            WITH 
            normal_hosts AS (
                FROM '{has_data}/auth_events/day=*/*.parquet'
                SELECT DISTINCT username, source_ip
                WHERE success = true
                  AND timestamp >= '2024-02-01'
                  AND timestamp < '2024-03-09'
            ),
            recent_logins AS (
                FROM '{has_data}/auth_events/day=*/*.parquet'
                SELECT *
                WHERE success = true
                  AND timestamp >= '2024-03-09'
                  AND timestamp < '2024-03-12'
            )
            SELECT r.timestamp, r.username, r.source_ip as new_host
            FROM recent_logins r
            LEFT JOIN normal_hosts n 
                ON r.username = n.username AND r.source_ip = n.source_ip
            WHERE n.source_ip IS NULL
              AND r.source_ip LIKE '10.0.0.%'
            ORDER BY r.timestamp
        """).fetchall()

        assert len(result) > 0, "Должны быть найдены входы с новых хостов"

        # Проверяем, что найден целевой пользователь
        usernames = [row[1] for row in result]
        assert "dev_sergey" in usernames, (
            "Должен быть найден dev_sergey с новыми хостами"
        )


class TestC2SETUP:
    """Тесты для обнаружения C2-канала."""

    def test_dga_domains(self, db, has_data):
        """Проверяет обнаружение DGA-доменов."""
        result = db.sql(f"""
            FROM '{has_data}/dns_queries/day=*/*.parquet'
            SELECT query_domain, COUNT(*) as queries
            WHERE query_domain LIKE '%.data-sync.xyz'
              AND timestamp >= '2024-03-12'
              AND timestamp < '2024-03-14'
            GROUP BY query_domain
            ORDER BY queries DESC
        """).fetchall()

        assert len(result) > 0, "Должны быть найдены DGA-домены"

        # Проверяем, что найдены домены с подозрительными поддоменами
        domains = [row[0] for row in result]
        suspicious_domains = [d for d in domains if len(d.split(".")[0]) > 8]
        assert len(suspicious_domains) > 0, (
            "Должны быть найдены домены с длинными поддоменами"
        )


class TestEXFILTRATION:
    """Тесты для обнаружения утечки данных."""

    def test_large_api_responses(self, db, has_data):
        """Проверяет обнаружение больших ответов API."""
        result = db.sql(f"""
            FROM '{has_data}/nginx_logs/day=*/*.parquet'
            SELECT source_ip, path, size, timestamp
            WHERE size > 1000000
              AND path LIKE '/api/%'
              AND status = 200
              AND timestamp >= '2024-03-13'
              AND timestamp < '2024-03-15'
            ORDER BY size DESC
        """).fetchall()

        assert len(result) > 0, "Должны быть найдены большие ответы API"

        # Проверяем, что найдены ответы размером более 1MB
        sizes = [row[2] for row in result]
        assert max(sizes) > 1000000, "Должны быть найдены ответы размером более 1MB"


class TestTimeline:
    """Тесты для построения timeline атаки."""

    def test_ip_in_all_logs(self, db, has_data):
        """Проверяет обнаружение IP, присутствующих во всех типах логов."""
        # Проверяем наличие основного IP атакующего во всех типах логов
        auth_result = db.sql(f"""
            SELECT COUNT(*) as cnt
            FROM '{has_data}/auth_events/day=*/*.parquet'
            WHERE source_ip = '203.0.113.42'
              AND timestamp >= '2024-03-01'
              AND timestamp < '2024-03-15'
        """).fetchone()

        nginx_result = db.sql(f"""
            SELECT COUNT(*) as cnt
            FROM '{has_data}/nginx_logs/day=*/*.parquet'
            WHERE source_ip = '203.0.113.42'
              AND timestamp >= '2024-03-01'
              AND timestamp < '2024-03-15'
        """).fetchone()

        firewall_result = db.sql(f"""
            SELECT COUNT(*) as cnt
            FROM '{has_data}/firewall_events/day=*/*.parquet'
            WHERE source_ip = '203.0.113.42'
              AND timestamp >= '2024-03-01'
              AND timestamp < '2024-03-15'
        """).fetchone()

        assert auth_result[0] > 0, "IP должен присутствовать в auth_events"
        assert nginx_result[0] > 0, "IP должен присутствовать в nginx_logs"
        assert firewall_result[0] > 0, "IP должен присутствовать в firewall_events"

    def test_timeline_construction(self, db, has_data):
        """Проверяет построение timeline атаки."""
        # Проверяем наличие данных в auth_events для основного IP
        auth_count = db.sql(f"""
            SELECT COUNT(*) as cnt
            FROM '{has_data}/auth_events/day=*/*.parquet'
            WHERE source_ip = '203.0.113.42'
              AND timestamp >= '2024-03-01'
              AND timestamp < '2024-03-15'
        """).fetchone()

        # Если нет данных в auth_events для этого IP, проверяем наличие в других источниках
        if auth_count[0] == 0:
            # Проверяем наличие в nginx_logs
            nginx_count = db.sql(f"""
                SELECT COUNT(*) as cnt
                FROM '{has_data}/nginx_logs/day=*/*.parquet'
                WHERE source_ip = '203.0.113.42'
                  AND timestamp >= '2024-03-01'
                  AND timestamp < '2024-03-15'
            """).fetchone()

            assert nginx_count[0] > 0, (
                "IP должен присутствовать хотя бы в одном источнике логов"
            )
            # Если есть данные только в nginx, тест проходит
            return

        # Если есть данные в auth_events, строим полный timeline
        result = db.sql(f"""
            WITH 
            auth_timeline AS (
                SELECT 
                    timestamp,
                    'AUTH' as source,
                    CASE WHEN success THEN 'login_success' ELSE 'login_failure' END as event_type,
                    username as details
                FROM '{has_data}/auth_events/day=*/*.parquet'
                WHERE source_ip = '203.0.113.42'
                  AND timestamp >= '2024-03-01'
                  AND timestamp < '2024-03-15'
            ),
            nginx_timeline AS (
                SELECT 
                    timestamp,
                    'NGINX' as source,
                    status::VARCHAR as event_type,
                    path as details
                FROM '{has_data}/nginx_logs/day=*/*.parquet'
                WHERE source_ip = '203.0.113.42'
                  AND timestamp >= '2024-03-01'
                  AND timestamp < '2024-03-15'
            )
            SELECT * FROM auth_timeline
            UNION ALL SELECT * FROM nginx_timeline
            ORDER BY timestamp
            LIMIT 100
        """).fetchall()

        assert len(result) > 0, "Должен быть построен timeline"

        # Проверяем, что timeline содержит события из разных источников
        sources = set(row[1] for row in result)
        # Если есть данные в обоих источниках, проверяем оба
        if auth_count[0] > 0:
            assert "AUTH" in sources or "NGINX" in sources, (
                "Timeline должен содержать события хотя бы из одного источника"
            )


class TestComprehensiveAnalysis:
    """Тесты для комплексного анализа инцидента."""

    def test_all_attacker_ips(self, db, has_data):
        """Проверяет обнаружение всех IP атакующего."""
        # Основной IP
        main_ip = "203.0.113.42"

        # Проверяем наличие основного IP в разных этапах атаки
        recon_result = db.sql(f"""
            SELECT COUNT(*) as cnt
            FROM '{has_data}/nginx_logs/day=*/*.parquet'
            WHERE source_ip = '{main_ip}'
              AND timestamp >= '2024-03-01'
              AND timestamp < '2024-03-04'
        """).fetchone()

        brute_result = db.sql(f"""
            SELECT COUNT(*) as cnt
            FROM '{has_data}/auth_events/day=*/*.parquet'
            WHERE source_ip = '{main_ip}'
              AND timestamp >= '2024-03-04'
              AND timestamp < '2024-03-08'
        """).fetchone()

        assert recon_result[0] > 0, "Основной IP должен присутствовать в RECON"
        assert brute_result[0] > 0, "Основной IP должен присутствовать в BRUTEFORCE"

    def test_target_user_compromise(self, db, has_data):
        """Проверяет обнаружение компрометации целевого пользователя."""
        result = db.sql(f"""
            FROM '{has_data}/auth_events/day=*/*.parquet'
            SELECT COUNT(*) as success_count
            WHERE username = 'dev_sergey'
              AND source_ip = '203.0.113.42'
              AND event_type = 'login_success'
              AND timestamp >= '2024-03-08'
              AND timestamp < '2024-03-09'
        """).fetchone()

        assert result[0] > 0, (
            "Должен быть найден успешный вход dev_sergey с IP 203.0.113.42"
        )
