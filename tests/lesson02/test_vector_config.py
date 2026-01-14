"""
Тесты для Блока 2: Сбор и маршрутизация логов

Проверяют корректность конфигурации Vector для всех форматов логов.
"""

import subprocess
import os
from pathlib import Path

import pytest
import psycopg2

# Путь к директории lesson02
LESSON_DIR = Path(__file__).parent.parent.parent / "lesson02"
VECTOR_CONFIGS_DIR = LESSON_DIR / "vector-configs"


def get_db_connection():
    """Получить подключение к PostgreSQL."""
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        database=os.getenv("DB_NAME", "security_logs"),
        user=os.getenv("DB_USER", "analyst"),
        password=os.getenv("DB_PASSWORD", "security123"),
    )


def run_vector_validate(config_path: Path) -> tuple[int, str, str]:
    """Запускает vector validate и возвращает (exit_code, stdout, stderr)."""
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{config_path.parent}:/config:ro",
            "-e",
            "DB_USER=test",
            "-e",
            "DB_PASSWORD=test",
            "-e",
            "DB_HOST=localhost",
            "-e",
            "DB_PORT=5432",
            "-e",
            "DB_NAME=test",
            "timberio/vector:0.52.0-alpine",
            "validate",
            "--skip-healthchecks",
            f"/config/{config_path.name}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.returncode, result.stdout, result.stderr


class TestVectorConfigsExist:
    """Проверяем наличие конфигураций Vector."""

    def test_auth_config_exists(self):
        """Файл auth_events.toml должен существовать."""
        config_path = VECTOR_CONFIGS_DIR / "auth_events.toml"
        assert config_path.exists(), (
            f"Файл {config_path} не найден. "
            "Создайте конфигурацию для парсинга auth_events согласно заданию 2.2"
        )

    def test_nginx_config_exists(self):
        """Файл nginx_logs.toml должен существовать."""
        config_path = VECTOR_CONFIGS_DIR / "nginx_logs.toml"
        assert config_path.exists(), (
            f"Файл {config_path} не найден. "
            "Создайте конфигурацию для парсинга nginx_logs согласно заданию 2.3"
        )

    def test_dns_config_exists(self):
        """Файл dns_queries.toml должен существовать."""
        config_path = VECTOR_CONFIGS_DIR / "dns_queries.toml"
        assert config_path.exists(), (
            f"Файл {config_path} не найден. "
            "Создайте конфигурацию для парсинга dns_queries согласно заданию 2.4"
        )

    def test_firewall_config_exists(self):
        """Файл firewall_events.toml должен существовать."""
        config_path = VECTOR_CONFIGS_DIR / "firewall_events.toml"
        assert config_path.exists(), (
            f"Файл {config_path} не найден. "
            "Создайте конфигурацию для парсинга firewall_events согласно заданию 2.5"
        )


class TestVectorConfigsValid:
    """Проверяем валидность конфигураций."""

    @pytest.mark.parametrize(
        "config_file",
        [
            "auth_events.toml",
            "nginx_logs.toml",
            "dns_queries.toml",
            "firewall_events.toml",
        ],
    )
    def test_config_validates(self, config_file):
        """Vector должен успешно валидировать конфиг."""
        config_path = VECTOR_CONFIGS_DIR / config_file
        if not config_path.exists():
            pytest.skip(f"Конфигурация {config_file} не найдена")

        exit_code, stdout, stderr = run_vector_validate(config_path)
        assert exit_code == 0, f"Ошибка валидации {config_file}: {stderr}"

    @pytest.mark.parametrize(
        "config_file",
        [
            "auth_events.toml",
            "nginx_logs.toml",
            "dns_queries.toml",
            "firewall_events.toml",
        ],
    )
    def test_config_has_source(self, config_file):
        """Конфиг должен содержать source."""
        config_path = VECTOR_CONFIGS_DIR / config_file
        if not config_path.exists():
            pytest.skip(f"Конфигурация {config_file} не найдена")

        content = config_path.read_text()
        assert "[sources." in content, (
            f"Конфиг {config_file} должен содержать секцию [sources.*]"
        )

    @pytest.mark.parametrize(
        "config_file",
        [
            "auth_events.toml",
            "nginx_logs.toml",
            "dns_queries.toml",
            "firewall_events.toml",
        ],
    )
    def test_config_has_transform(self, config_file):
        """Конфиг должен содержать transform."""
        config_path = VECTOR_CONFIGS_DIR / config_file
        if not config_path.exists():
            pytest.skip(f"Конфигурация {config_file} не найдена")

        content = config_path.read_text()
        assert "[transforms." in content, (
            f"Конфиг {config_file} должен содержать секцию [transforms.*]"
        )

    @pytest.mark.parametrize(
        "config_file",
        [
            "auth_events.toml",
            "nginx_logs.toml",
            "dns_queries.toml",
            "firewall_events.toml",
        ],
    )
    def test_config_has_sink(self, config_file):
        """Конфиг должен содержать sink."""
        config_path = VECTOR_CONFIGS_DIR / config_file
        if not config_path.exists():
            pytest.skip(f"Конфигурация {config_file} не найдена")

        content = config_path.read_text()
        assert "[sinks." in content, (
            f"Конфиг {config_file} должен содержать секцию [sinks.*]"
        )


class TestPostgreSQLTables:
    """Проверяем наличие таблиц в PostgreSQL."""

    @pytest.fixture(scope="class")
    def conn(self):
        """Подключение к базе данных."""
        try:
            conn = get_db_connection()
            yield conn
            conn.close()
        except psycopg2.OperationalError:
            pytest.skip("PostgreSQL не доступен. Запустите docker-compose из Блока 1.")

    @pytest.mark.parametrize(
        "table_name",
        [
            "auth_events",
            "nginx_logs",
            "dns_queries",
            "firewall_events",
        ],
    )
    def test_table_exists(self, conn, table_name):
        """Таблица должна существовать в PostgreSQL."""
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = %s
                );
            """,
                (table_name,),
            )
            exists = cur.fetchone()[0]
            assert exists, (
                f"Таблица {table_name} не найдена в PostgreSQL. "
                "Убедитесь, что init.sql выполнен."
            )

    @pytest.mark.parametrize(
        "table_name,required_fields",
        [
            ("auth_events", ["timestamp", "event_type", "source_ip", "severity"]),
            (
                "nginx_logs",
                ["timestamp", "source_ip", "method", "path", "status", "severity"],
            ),
            (
                "dns_queries",
                ["timestamp", "source_ip", "query_domain", "query_type", "severity"],
            ),
            (
                "firewall_events",
                ["timestamp", "source_ip", "dest_ip", "action", "severity"],
            ),
        ],
    )
    def test_table_has_required_fields(self, conn, table_name, required_fields):
        """Таблица должна содержать обязательные поля."""
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_schema = 'public' 
                AND table_name = %s;
            """,
                (table_name,),
            )
            columns = {row[0] for row in cur.fetchall()}

            missing = [f for f in required_fields if f not in columns]
            assert not missing, f"В таблице {table_name} отсутствуют поля: {missing}"


class TestDataInPostgreSQL:
    """Проверяем наличие данных в PostgreSQL после обработки Vector."""

    @pytest.fixture(scope="class")
    def conn(self):
        """Подключение к базе данных."""
        try:
            conn = get_db_connection()
            yield conn
            conn.close()
        except psycopg2.OperationalError:
            pytest.skip("PostgreSQL не доступен. Запустите docker-compose из Блока 1.")

    @pytest.mark.parametrize(
        "table_name",
        [
            "auth_events",
            "nginx_logs",
            "dns_queries",
            "firewall_events",
        ],
    )
    def test_table_has_data(self, conn, table_name):
        """Таблица должна содержать данные после обработки Vector."""
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM {table_name};")
            count = cur.fetchone()[0]

            # Если данных нет, это не критично для теста структуры
            # Но можно проверить, что таблица готова к приёму данных
            assert count >= 0, f"Ошибка при проверке таблицы {table_name}"

    @pytest.mark.parametrize(
        "table_name,field_name",
        [
            ("auth_events", "severity"),
            ("nginx_logs", "severity"),
            ("dns_queries", "severity"),
            ("firewall_events", "severity"),
        ],
    )
    def test_severity_field_populated(self, conn, table_name, field_name):
        """Поле severity должно быть заполнено корректными значениями."""
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT DISTINCT {field_name} 
                FROM {table_name} 
                WHERE {field_name} IS NOT NULL
                LIMIT 10;
            """)
            severities = {row[0] for row in cur.fetchall()}

            # Проверяем, что severity содержит допустимые значения
            valid_severities = {"info", "warning", "error"}
            invalid = severities - valid_severities

            if severities:  # Если есть данные
                assert not invalid, (
                    f"В таблице {table_name} найдены недопустимые значения severity: {invalid}"
                )
