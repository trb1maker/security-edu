"""
Тесты для проверки наличия и структуры данных Блока 1.

Проверяет:
- Наличие загруженных Parquet-файлов
- Корректность структуры директорий
- Наличие manifest.json
- Валидность Parquet-файлов
- Запуск и доступность PostgreSQL
"""

import json
import os
import subprocess
from pathlib import Path

import pyarrow.parquet as pq
import pytest

try:
    import psycopg2
except ImportError:
    psycopg2 = None

try:
    import yaml
except ImportError:
    yaml = None


def find_project_root() -> Path:
    """Найти корневую директорию проекта."""
    current = Path(__file__).resolve()
    while current != current.parent:
        if (current / "pyproject.toml").exists():
            return current
        current = current.parent
    raise RuntimeError("Не удалось найти корень проекта")


PROJECT_ROOT = find_project_root()
DATA_DIR = PROJECT_ROOT / "data"
LESSON01_DIR = PROJECT_ROOT / "lesson01"

# Параметры подключения к PostgreSQL (можно переопределить через переменные окружения)
PG_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "database": os.getenv("DB_NAME", "security_logs"),
    "user": os.getenv("DB_USER", "analyst"),
    "password": os.getenv("DB_PASSWORD", "security123"),
}


@pytest.fixture
def data_versions():
    """Версии данных для проверки."""
    versions = []
    if (DATA_DIR / "lite").exists():
        versions.append("lite")
    if (DATA_DIR / "full").exists():
        versions.append("full")
    return versions


def test_data_directory_exists():
    """Проверка наличия директории data/."""
    assert DATA_DIR.exists(), (
        f"Директория {DATA_DIR} не найдена. Запустите bootstrap.py для загрузки данных."
    )


def test_at_least_one_version_exists(data_versions):
    """Проверка наличия хотя бы одной версии данных."""
    assert len(data_versions) > 0, (
        "Не найдено ни одной версии данных. "
        "Запустите: uv run python bootstrap.py --version lite"
    )


@pytest.mark.parametrize("version", ["lite", "full"])
def test_version_directory_exists(version):
    """Проверка наличия директории версии."""
    version_dir = DATA_DIR / version
    if not version_dir.exists():
        pytest.skip(f"Версия {version} не загружена. Пропускаем тест.")

    assert version_dir.is_dir(), f"Директория {version_dir} должна быть директорией"


@pytest.mark.parametrize("version", ["lite", "full"])
def test_manifest_exists(version):
    """Проверка наличия manifest.json."""
    manifest_path = DATA_DIR / version / "manifest.json"
    if not manifest_path.exists():
        pytest.skip(f"Версия {version} не загружена. Пропускаем тест.")

    assert manifest_path.exists(), f"Файл manifest.json не найден в {version}"

    # Проверка валидности JSON
    with open(manifest_path) as f:
        manifest = json.load(f)

    assert "version" in manifest, "manifest.json должен содержать поле 'version'"
    assert manifest["version"] == version, f"Версия в manifest должна быть {version}"
    assert "files" in manifest, "manifest.json должен содержать поле 'files'"
    assert len(manifest["files"]) > 0, "manifest.json должен содержать список файлов"


@pytest.mark.parametrize("version", ["lite", "full"])
@pytest.mark.parametrize(
    "data_type", ["auth_events", "nginx_logs", "dns_queries", "firewall_events"]
)
def test_data_type_directory_exists(version, data_type):
    """Проверка наличия директорий для каждого типа данных."""
    data_type_dir = DATA_DIR / version / data_type
    if not data_type_dir.exists():
        pytest.skip(f"Версия {version} не загружена. Пропускаем тест.")

    assert data_type_dir.exists(), f"Директория {data_type_dir} не найдена"
    assert data_type_dir.is_dir(), f"{data_type_dir} должна быть директорией"


@pytest.mark.parametrize("version", ["lite", "full"])
@pytest.mark.parametrize(
    "data_type", ["auth_events", "nginx_logs", "dns_queries", "firewall_events"]
)
def test_parquet_files_exist(version, data_type):
    """Проверка наличия Parquet-файлов."""
    data_type_dir = DATA_DIR / version / data_type
    if not data_type_dir.exists():
        pytest.skip(f"Версия {version} не загружена. Пропускаем тест.")

    # Ищем Parquet-файлы в поддиректориях day=*
    parquet_files = list(data_type_dir.glob("day=*/part-*.parquet"))

    assert len(parquet_files) > 0, (
        f"Не найдено Parquet-файлов в {data_type_dir}. "
        "Убедитесь, что данные загружены полностью."
    )


@pytest.mark.parametrize("version", ["lite", "full"])
@pytest.mark.parametrize(
    "data_type", ["auth_events", "nginx_logs", "dns_queries", "firewall_events"]
)
def test_parquet_files_valid(version, data_type):
    """Проверка валидности Parquet-файлов."""
    data_type_dir = DATA_DIR / version / data_type
    if not data_type_dir.exists():
        pytest.skip(f"Версия {version} не загружена. Пропускаем тест.")

    # Берем первый найденный файл для проверки
    parquet_files = list(data_type_dir.glob("day=*/part-*.parquet"))
    if not parquet_files:
        pytest.skip(f"Нет Parquet-файлов в {data_type_dir}")

    test_file = parquet_files[0]

    try:
        # Попытка открыть Parquet-файл
        table = pq.read_table(test_file)
        assert table.num_rows > 0, f"Parquet-файл {test_file} пуст"
        assert len(table.schema) > 0, f"Parquet-файл {test_file} не содержит колонок"
    except Exception as e:
        pytest.fail(f"Ошибка при чтении Parquet-файла {test_file}: {e}")


@pytest.mark.parametrize("version", ["lite", "full"])
def test_manifest_files_match_actual_files(version):
    """Проверка соответствия файлов в manifest.json реальным файлам."""
    manifest_path = DATA_DIR / version / "manifest.json"
    if not manifest_path.exists():
        pytest.skip(f"Версия {version} не загружена. Пропускаем тест.")

    with open(manifest_path) as f:
        manifest = json.load(f)

    # Проверяем, что файлы из manifest существуют
    missing_files = []
    for file_info in manifest.get("files", []):
        file_path = DATA_DIR / version / file_info["name"]
        if not file_path.exists():
            missing_files.append(file_info["name"])

    assert len(missing_files) == 0, (
        f"Следующие файлы указаны в manifest.json, но отсутствуют на диске: {missing_files}"
    )


# ============================================================================
# Тесты для PostgreSQL
# ============================================================================


def test_docker_compose_file_exists():
    """Проверка наличия docker-compose.yml (задание студента)."""
    compose_file = LESSON01_DIR / "docker-compose.yml"

    if not compose_file.exists():
        pytest.skip(
            f"Файл docker-compose.yml не найден в {LESSON01_DIR}. "
            "Это нормально - создайте его согласно заданию 1.2 из README.md. "
            "После создания файла этот тест будет проверять его структуру."
        )

    # Если файл существует, проверяем его базовую структуру
    if yaml is None:
        pytest.skip("PyYAML не установлен. Установите: uv sync")

    try:
        with open(compose_file) as f:
            compose_data = yaml.safe_load(f)

        assert compose_data is not None, "docker-compose.yml не является валидным YAML"
        assert "services" in compose_data, (
            "docker-compose.yml должен содержать секцию 'services'"
        )
        assert "postgres" in compose_data["services"], (
            "docker-compose.yml должен содержать сервис 'postgres'"
        )
    except Exception as e:
        pytest.fail(f"Ошибка при чтении docker-compose.yml: {e}")


def test_postgres_container_running():
    """Проверка, что контейнер PostgreSQL запущен."""
    try:
        result = subprocess.run(
            [
                "docker",
                "ps",
                "--filter",
                "name=security-postgres",
                "--format",
                "{{.Names}}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode != 0:
            pytest.skip("Docker недоступен или команда docker ps не работает")

        containers = result.stdout.strip().split("\n")
        containers = [c for c in containers if c]  # Убираем пустые строки

        assert len(containers) > 0, (
            "Контейнер security-postgres не запущен. "
            "Запустите: cd lesson01 && docker compose up -d"
        )

        assert "security-postgres" in containers, (
            f"Контейнер security-postgres не найден. Найдены контейнеры: {containers}"
        )
    except FileNotFoundError:
        pytest.skip("Docker не установлен или не доступен в PATH")
    except subprocess.TimeoutExpired:
        pytest.fail("Команда docker ps выполняется слишком долго")


def test_postgres_connection():
    """Проверка подключения к PostgreSQL."""
    if psycopg2 is None:
        pytest.skip("psycopg2 не установлен. Запустите: uv sync")

    try:
        conn = psycopg2.connect(**PG_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        result = cursor.fetchone()
        cursor.close()
        conn.close()

        assert result is not None, "Не удалось получить версию PostgreSQL"
        assert "PostgreSQL" in result[0], (
            f"Неожиданный ответ от PostgreSQL: {result[0]}"
        )
    except psycopg2.OperationalError as e:
        pytest.fail(
            f"Не удалось подключиться к PostgreSQL: {e}\n"
            f"Проверьте:\n"
            f"1. Контейнер запущен: docker compose ps (в директории lesson01)\n"
            f"2. Параметры подключения корректны (DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD)\n"
            f"3. База данных создана"
        )


def test_postgres_database_exists():
    """Проверка, что база данных существует."""
    if psycopg2 is None:
        pytest.skip("psycopg2 не установлен. Запустите: uv sync")

    # Подключаемся к базе postgres для проверки существования целевой БД
    check_config = PG_CONFIG.copy()
    check_config["database"] = "postgres"

    try:
        conn = psycopg2.connect(**check_config)
        cursor = conn.cursor()

        # Проверяем, что база данных существует
        cursor.execute(
            "SELECT datname FROM pg_database WHERE datname = %s",
            (PG_CONFIG["database"],),
        )
        result = cursor.fetchone()

        cursor.close()
        conn.close()

        assert result is not None, (
            f"База данных '{PG_CONFIG['database']}' не существует. "
            "Убедитесь, что PostgreSQL запущен с правильными переменными окружения."
        )
    except psycopg2.OperationalError as e:
        pytest.skip(f"PostgreSQL недоступен: {e}")


def test_postgres_user_exists():
    """Проверка, что пользователь базы данных существует."""
    if psycopg2 is None:
        pytest.skip("psycopg2 не установлен. Запустите: uv sync")

    try:
        conn = psycopg2.connect(**PG_CONFIG)
        cursor = conn.cursor()

        # Проверяем текущего пользователя
        cursor.execute("SELECT current_user;")
        result = cursor.fetchone()

        cursor.close()
        conn.close()

        assert result is not None, "Не удалось получить текущего пользователя"
        assert result[0] == PG_CONFIG["user"], (
            f"Текущий пользователь '{result[0]}' не совпадает с ожидаемым '{PG_CONFIG['user']}'"
        )
    except psycopg2.OperationalError as e:
        pytest.skip(f"PostgreSQL недоступен: {e}")


def test_data_loaded_to_postgres():
    """Проверка, что данные загружены в PostgreSQL (задание 1.3)."""
    if psycopg2 is None:
        pytest.skip("psycopg2 не установлен. Запустите: uv sync")

    try:
        conn = psycopg2.connect(**PG_CONFIG)
        cursor = conn.cursor()

        # Проверяем наличие таблицы auth_events
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'auth_events'
            )
        """)
        table_exists = cursor.fetchone()[0]

        if not table_exists:
            pytest.skip(
                "Таблица auth_events не существует. "
                "Выполните задание 1.3: создайте скрипт load_data.py и загрузите данные."
            )

        # Проверяем наличие данных
        cursor.execute("SELECT COUNT(*) FROM auth_events")
        row_count = cursor.fetchone()[0]

        cursor.close()
        conn.close()

        assert row_count > 0, (
            f"Таблица auth_events существует, но пуста ({row_count} строк). "
            "Загрузите данные через скрипт load_data.py (задание 1.3)."
        )

        # Минимальное количество данных для версии lite (14 дней * ~50k событий/день = ~700k минимум)
        # Но для теста достаточно проверить, что есть хотя бы какие-то данные
        assert row_count >= 1000, (
            f"В таблице auth_events слишком мало данных: {row_count} строк. "
            "Возможно, загрузка не завершилась полностью."
        )
    except psycopg2.OperationalError as e:
        pytest.skip(f"PostgreSQL недоступен: {e}")
