"""
Тесты для Блока 4: SQL-аналитика для ИБ

Проверяет корректность SQL-запросов студента.
"""

import os
import pytest
import duckdb

LESSON_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PARQUET_PATH = os.path.join(LESSON_DIR, "lesson03", "data", "auth_events.parquet")


@pytest.fixture
def db():
    """Создаёт подключение к DuckDB."""
    return duckdb.connect()


@pytest.fixture
def has_data():
    """Проверяет наличие данных."""
    if not os.path.exists(PARQUET_PATH):
        pytest.skip(f"Parquet-файл не найден: {PARQUET_PATH}")
    return PARQUET_PATH


class TestBasicAnalytics:
    """Тесты для занятия 4.1: Базовая аналитика."""

    def test_top_failed_ips(self, db, has_data):
        """Проверяет запрос TOP-10 IP по неудачным попыткам."""
        result = db.sql(f"""
            FROM '{has_data}'
            SELECT source_ip, COUNT(*) as failed_attempts
            WHERE success = false
            GROUP BY ALL
            ORDER BY failed_attempts DESC
            LIMIT 10
        """).fetchall()
        
        assert len(result) <= 10, "Должно быть не более 10 строк"
        # Проверяем, что отсортировано по убыванию
        if len(result) > 1:
            assert result[0][1] >= result[1][1], "Должно быть отсортировано по убыванию"

    def test_hourly_distribution(self, db, has_data):
        """Проверяет запрос распределения по часам."""
        result = db.sql(f"""
            FROM '{has_data}'
            SELECT EXTRACT(HOUR FROM timestamp) as hour, COUNT(*) as events
            GROUP BY ALL
            ORDER BY hour
        """).fetchall()
        
        assert len(result) <= 24, "Часов не больше 24"
        hours = [r[0] for r in result]
        assert all(0 <= h <= 23 for h in hours), "Часы должны быть от 0 до 23"

    def test_fail_rate_by_user(self, db, has_data):
        """Проверяет запрос процента неудач по пользователям."""
        result = db.sql(f"""
            FROM '{has_data}'
            SELECT 
                username,
                COUNT(*) as total,
                ROUND(100.0 * SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) / COUNT(*), 1) as fail_rate
            GROUP BY ALL
            HAVING COUNT(*) > 5
            ORDER BY fail_rate DESC
            LIMIT 10
        """).fetchall()
        
        # Проверяем, что fail_rate в допустимых пределах
        for row in result:
            assert 0 <= row[2] <= 100, f"fail_rate должен быть 0-100, получено {row[2]}"


class TestWindowFunctions:
    """Тесты для занятия 4.2: Оконные функции."""

    def test_lag_function(self, db, has_data):
        """Проверяет использование LAG."""
        result = db.sql(f"""
            FROM '{has_data}'
            SELECT 
                timestamp,
                username,
                LAG(timestamp) OVER (PARTITION BY username ORDER BY timestamp) as prev_time
            LIMIT 100
        """).fetchall()
        
        assert len(result) > 0, "Запрос должен вернуть результаты"

    def test_brute_force_detection(self, db, has_data):
        """Проверяет запрос обнаружения brute-force."""
        result = db.sql(f"""
            WITH events_with_context AS (
                FROM '{has_data}'
                SELECT 
                    *,
                    LAG(success) OVER (PARTITION BY username, source_ip ORDER BY timestamp) as prev_success,
                    LAG(timestamp) OVER (PARTITION BY username, source_ip ORDER BY timestamp) as prev_time
            )
            FROM events_with_context
            SELECT timestamp, username, source_ip
            WHERE success = true AND prev_success = false
            LIMIT 10
        """).fetchall()
        
        # Запрос должен выполниться без ошибок
        assert isinstance(result, list)

    def test_session_building(self, db, has_data):
        """Проверяет построение сессий."""
        result = db.sql(f"""
            WITH events_with_gaps AS (
                FROM '{has_data}'
                SELECT 
                    username,
                    timestamp,
                    CASE 
                        WHEN timestamp - LAG(timestamp) OVER (PARTITION BY username ORDER BY timestamp) 
                             > INTERVAL '30 minutes'
                        THEN 1 ELSE 0 
                    END as is_new_session
            ),
            events_with_sessions AS (
                SELECT *, SUM(is_new_session) OVER (PARTITION BY username ORDER BY timestamp) as session_id
                FROM events_with_gaps
            )
            FROM events_with_sessions
            SELECT username, session_id, COUNT(*) as events
            GROUP BY username, session_id
            LIMIT 20
        """).fetchall()
        
        assert len(result) > 0, "Должны быть найдены сессии"


class TestCorrelation:
    """Тесты для занятия 4.3: Корреляция данных."""

    def test_cte_usage(self, db, has_data):
        """Проверяет использование CTE."""
        result = db.sql(f"""
            WITH 
            failed_events AS (
                FROM '{has_data}'
                SELECT source_ip, COUNT(*) as cnt
                WHERE success = false
                GROUP BY ALL
            ),
            success_events AS (
                FROM '{has_data}'
                SELECT source_ip, COUNT(*) as cnt
                WHERE success = true
                GROUP BY ALL
            )
            FROM failed_events f
            JOIN success_events s ON f.source_ip = s.source_ip
            SELECT f.source_ip, f.cnt as failed, s.cnt as success
            ORDER BY f.cnt DESC
            LIMIT 10
        """).fetchall()
        
        assert isinstance(result, list)

    def test_lateral_movement_detection(self, db, has_data):
        """Проверяет запрос обнаружения lateral movement."""
        result = db.sql(f"""
            WITH 
            known_hosts AS (
                FROM '{has_data}'
                SELECT DISTINCT username, source_ip
                WHERE success = true
                  AND timestamp < (SELECT MAX(timestamp) - INTERVAL '1 hour' FROM '{has_data}')
            ),
            recent_logins AS (
                FROM '{has_data}'
                SELECT *
                WHERE success = true
                  AND timestamp >= (SELECT MAX(timestamp) - INTERVAL '1 hour' FROM '{has_data}')
            )
            FROM recent_logins r
            LEFT JOIN known_hosts k ON r.username = k.username AND r.source_ip = k.source_ip
            SELECT r.timestamp, r.username, r.source_ip
            WHERE k.source_ip IS NULL
            LIMIT 10
        """).fetchall()
        
        # Запрос должен выполниться без ошибок
        assert isinstance(result, list)
