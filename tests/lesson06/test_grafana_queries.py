"""
Тесты для Блока 6: Визуализация и дашборды

Проверяет корректность SQL-запросов для Grafana.
Основная работа с Grafana выполняется в UI и проверяется визуально.
"""

import os
import pytest
import duckdb


PARQUET_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "lesson03",
    "data",
    "auth_events.parquet",
)


@pytest.fixture
def has_data():
    """Проверяет наличие данных."""
    if not os.path.exists(PARQUET_PATH):
        pytest.skip("Parquet-файл не найден")
    return PARQUET_PATH


class TestGrafanaQueries:
    """Тесты SQL-запросов для панелей Grafana."""

    def test_time_series_query(self, has_data):
        """Проверяет запрос для Time Series панели."""
        result = duckdb.sql(f"""
            FROM '{has_data}'
            SELECT 
                DATE_TRUNC('hour', timestamp) as time,
                SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful,
                SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) as failed
            GROUP BY ALL
            ORDER BY time
        """).fetchall()

        assert len(result) > 0, "Запрос должен вернуть данные"
        # Проверяем структуру
        assert len(result[0]) == 3, "Должно быть 3 колонки: time, successful, failed"

    def test_stat_query(self, has_data):
        """Проверяет запрос для Stat панели."""
        result = duckdb.sql(f"""
            FROM '{has_data}'
            SELECT COUNT(*) as failed_total
            WHERE success = false
        """).fetchone()

        assert result is not None
        assert result[0] >= 0, "Количество должно быть неотрицательным"

    def test_bar_chart_query(self, has_data):
        """Проверяет запрос для Bar Chart панели."""
        result = duckdb.sql(f"""
            FROM '{has_data}'
            SELECT source_ip, COUNT(*) as failed_count
            WHERE success = false
            GROUP BY ALL
            ORDER BY failed_count DESC
            LIMIT 10
        """).fetchall()

        assert len(result) <= 10, "Должно быть не более 10 строк"
        # Проверяем сортировку
        if len(result) > 1:
            assert result[0][1] >= result[1][1], "Должно быть отсортировано по убыванию"

    def test_table_query(self, has_data):
        """Проверяет запрос для Table панели."""
        result = duckdb.sql(f"""
            FROM '{has_data}'
            SELECT timestamp, username, source_ip, event_type
            WHERE success = false
            ORDER BY timestamp DESC
            LIMIT 20
        """).fetchall()

        assert len(result) <= 20, "Должно быть не более 20 строк"


class TestAlertQueries:
    """Тесты запросов для алертов."""

    def test_brute_force_alert_query(self, has_data):
        """Проверяет запрос для алерта brute-force."""
        # Запрос должен выполниться без ошибок
        result = duckdb.sql(f"""
            FROM '{has_data}'
            SELECT source_ip, COUNT(*) as failed
            WHERE success = false
            GROUP BY source_ip
            HAVING COUNT(*) > 5
        """).fetchall()

        assert isinstance(result, list)

    def test_night_login_alert_query(self, has_data):
        """Проверяет запрос для алерта входа в нерабочее время."""
        result = duckdb.sql(f"""
            FROM '{has_data}'
            SELECT COUNT(*) as night_logins
            WHERE success = true
              AND (EXTRACT(HOUR FROM timestamp) < 6 OR EXTRACT(HOUR FROM timestamp) > 22)
        """).fetchone()

        assert result is not None
        assert result[0] >= 0
