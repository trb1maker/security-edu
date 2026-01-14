"""
Скрипт для загрузки данных из Parquet-файлов в PostgreSQL.

Использование:
    python load_data.py --version lite --table auth_events
    python load_data.py --version lite --table nginx_logs
"""

import argparse
import os
import sys
from pathlib import Path

try:
    import duckdb
except ImportError as e:
    print(f"Ошибка: не установлены необходимые библиотеки: {e}")
    print("Запустите: uv sync")
    sys.exit(1)


def find_project_root() -> Path:
    """Найти корневую директорию проекта."""
    current = Path(__file__).resolve()
    while current != current.parent:
        if (current / "pyproject.toml").exists():
            return current
        current = current.parent
    raise RuntimeError("Не удалось найти корень проекта")


def load_parquet_to_postgres(data_path: Path, table_name: str) -> None:
    """Загрузить данные из Parquet в PostgreSQL через DuckDB."""
    # TODO: Реализуйте загрузку данных через DuckDB
    # 
    # Подсказки:
    # 1. Получите параметры подключения к PostgreSQL из переменных окружения:
    #    - DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
    # 
    # 2. Проверьте наличие Parquet-файлов в data_path:
    #    - Используйте glob для поиска: data_path.glob("day=*/part-*.parquet")
    # 
    # 3. Подключитесь к DuckDB:
    #    - duckdb_conn = duckdb.connect()
    # 
    # 4. Подключите PostgreSQL через DuckDB:
    #    - Используйте ATTACH с connection string:
    #      attach 'host=... port=... dbname=... user=... password=...' as p (type postgres)
    # 
    # 5. Загрузите данные одной командой:
    #    - Используйте CREATE OR REPLACE TABLE ... AS FROM read_parquet(...)
    #    - Пример: create or replace table p.public.{table_name} as from read_parquet('{data_path}');
    # 
    # 6. Получите количество загруженных строк:
    #    - Выполните SELECT COUNT(*) FROM p.public.{table_name}
    # 
    # Примечание: DuckDB автоматически определит схему из Parquet и создаст таблицу в PostgreSQL
    
    print(f"Загрузка данных из {data_path} в таблицу {table_name}...")
    
    # Ваш код здесь
    pass


def main():
    """Главная функция."""
    parser = argparse.ArgumentParser(
        description="Загрузка данных из Parquet в PostgreSQL"
    )
    parser.add_argument(
        "--version",
        choices=["lite", "full"],
        required=True,
        help="Версия датасета",
    )
    parser.add_argument(
        "--table",
        choices=["auth_events", "nginx_logs", "dns_queries", "firewall_events"],
        required=True,
        help="Таблица для загрузки",
    )

    args = parser.parse_args()

    # Определить путь к данным
    # В контейнере данные монтируются в /data, локально - в project_root/data
    if Path("/data").exists():
        data_path = Path("/data") / args.version / args.table
    else:
        project_root = find_project_root()
        data_path = project_root / "data" / args.version / args.table

    if not data_path.exists():
        print(f"Ошибка: директория {data_path} не найдена")
        print("Запустите сначала: uv run bootstrap.py --version lite")
        sys.exit(1)

    # Загрузить данные
    try:
        load_parquet_to_postgres(data_path, args.table)
        print(f"✓ Данные загружены в таблицу {args.table}")
    except Exception as e:
        print(f"✗ Ошибка загрузки данных: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
