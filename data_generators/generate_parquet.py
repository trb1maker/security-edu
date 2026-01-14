"""
Скрипт для генерации данных в формате Parquet.

Использование:
    python -m data_generators.generate_parquet --version lite --output-dir data/lite
    python -m data_generators.generate_parquet --version full --output-dir data/full
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from tqdm import tqdm

from data_generators.auth_generator import AuthGenerator
from data_generators.dns_generator import DnsGenerator
from data_generators.firewall_generator import FirewallGenerator
from data_generators.nginx_generator import NginxGenerator
from data_generators.scenario_controller import TimelineEngine


def generate_auth_events(timeline: TimelineEngine, output_dir: Path, days: list[int]):
    """Генерировать события аутентификации."""
    generator = AuthGenerator(timeline)

    # Схема для PyArrow Table
    schema = pa.schema(
        [
            pa.field("timestamp", pa.string()),
            pa.field("event_type", pa.string()),
            pa.field("username", pa.string()),
            pa.field("source_ip", pa.string()),
            pa.field("success", pa.bool_()),
            pa.field("details", pa.string()),  # JSON как строка
        ]
    )

    total_events = 0

    # Генерировать и сохранять по дням
    for day in tqdm(days, desc="Auth events"):
        # Генерировать события за день
        events = generator.generate_day(day)

        if events:
            # Преобразовать в PyArrow Table
            day_data = {
                "timestamp": [e["timestamp"] for e in events],
                "event_type": [e["event_type"] for e in events],
                "username": [e["username"] for e in events],
                "source_ip": [e["source_ip"] for e in events],
                "success": [e["success"] for e in events],
                "details": [json.dumps(e["details"]) for e in events],
            }
            day_table = pa.Table.from_pydict(day_data, schema=schema)

            # Сохранить на диск
            day_dir = output_dir / "auth_events" / f"day={day}"
            day_dir.mkdir(parents=True, exist_ok=True)
            pq.write_table(day_table, day_dir / "part-0.parquet")

            total_events += len(events)

    return total_events


def generate_nginx_logs(timeline: TimelineEngine, output_dir: Path, days: list[int]):
    """Генерировать веб-логи."""
    generator = NginxGenerator(timeline)

    # Схема для PyArrow Table
    schema = pa.schema(
        [
            pa.field("timestamp", pa.timestamp("us")),
            pa.field("source_ip", pa.string()),
            pa.field("method", pa.string()),
            pa.field("path", pa.string()),
            pa.field("status", pa.int32()),
            pa.field("size", pa.int64()),
            pa.field("referer", pa.string()),
            pa.field("user_agent", pa.string()),
        ]
    )

    total_logs = 0

    # Генерировать и сохранять по дням
    for day in tqdm(days, desc="Nginx logs"):
        # Генерировать логи за день
        logs = generator.generate_day(day)

        if logs:
            # Преобразовать в PyArrow Table
            day_data = {
                "timestamp": [log["timestamp"] for log in logs],
                "source_ip": [log["source_ip"] for log in logs],
                "method": [log["method"] for log in logs],
                "path": [log["path"] for log in logs],
                "status": [log["status"] for log in logs],
                "size": [log["size"] for log in logs],
                "referer": [log["referer"] for log in logs],
                "user_agent": [log["user_agent"] for log in logs],
            }
            day_table = pa.Table.from_pydict(day_data, schema=schema)

            # Сохранить на диск
            day_dir = output_dir / "nginx_logs" / f"day={day}"
            day_dir.mkdir(parents=True, exist_ok=True)
            pq.write_table(day_table, day_dir / "part-0.parquet")

            total_logs += len(logs)

    return total_logs


def generate_dns_queries(timeline: TimelineEngine, output_dir: Path, days: list[int]):
    """Генерировать DNS-запросы."""
    generator = DnsGenerator(timeline)

    # Схема для PyArrow Table
    schema = pa.schema(
        [
            pa.field("timestamp", pa.timestamp("us")),
            pa.field("source_ip", pa.string()),
            pa.field("source_port", pa.int32()),
            pa.field("query_domain", pa.string()),
            pa.field("query_type", pa.string()),
            pa.field("response_code", pa.string()),
            pa.field("resolved_ip", pa.string()),
            pa.field("resolver", pa.string()),
        ]
    )

    total_queries = 0

    # Генерировать и сохранять по дням
    for day in tqdm(days, desc="DNS queries"):
        # Генерировать запросы за день
        queries = generator.generate_day(day)

        if queries:
            # Преобразовать в PyArrow Table
            day_data = {
                "timestamp": [q["timestamp"] for q in queries],
                "source_ip": [q["source_ip"] for q in queries],
                "source_port": [q["source_port"] for q in queries],
                "query_domain": [q["query_domain"] for q in queries],
                "query_type": [q["query_type"] for q in queries],
                "response_code": [q["response_code"] for q in queries],
                "resolved_ip": [q.get("resolved_ip") or "" for q in queries],
                "resolver": [q.get("resolver") or "" for q in queries],
            }
            day_table = pa.Table.from_pydict(day_data, schema=schema)

            # Сохранить на диск
            day_dir = output_dir / "dns_queries" / f"day={day}"
            day_dir.mkdir(parents=True, exist_ok=True)
            pq.write_table(day_table, day_dir / "part-0.parquet")

            total_queries += len(queries)

    return total_queries


def generate_firewall_events(
    timeline: TimelineEngine, output_dir: Path, days: list[int]
):
    """Генерировать события фаервола."""
    generator = FirewallGenerator(timeline)

    # Схема для PyArrow Table
    schema = pa.schema(
        [
            pa.field("timestamp", pa.timestamp("us")),
            pa.field("source_ip", pa.string()),
            pa.field("dest_ip", pa.string()),
            pa.field("source_port", pa.int32()),
            pa.field("dest_port", pa.int32()),
            pa.field("protocol", pa.string()),
            pa.field("action", pa.string()),
            pa.field("bytes_sent", pa.int64()),
            pa.field("bytes_received", pa.int64()),
            pa.field("reason", pa.string()),
        ]
    )

    total_events = 0

    # Генерировать и сохранять по дням
    for day in tqdm(days, desc="Firewall events"):
        # Генерировать события за день
        events = generator.generate_day(day)

        if events:
            # Преобразовать в PyArrow Table
            day_data = {
                "timestamp": [e["timestamp"] for e in events],
                "source_ip": [e["source_ip"] for e in events],
                "dest_ip": [e["dest_ip"] for e in events],
                "source_port": [e["source_port"] for e in events],
                "dest_port": [e["dest_port"] for e in events],
                "protocol": [e["protocol"] for e in events],
                "action": [e["action"] for e in events],
                "bytes_sent": [e["bytes_sent"] for e in events],
                "bytes_received": [e["bytes_received"] for e in events],
                "reason": [e["reason"] for e in events],
            }
            day_table = pa.Table.from_pydict(day_data, schema=schema)

            # Сохранить на диск
            day_dir = output_dir / "firewall_events" / f"day={day}"
            day_dir.mkdir(parents=True, exist_ok=True)
            pq.write_table(day_table, day_dir / "part-0.parquet")

            total_events += len(events)

    return total_events


def create_manifest(output_dir: Path, version: str, files_info: list[dict]) -> dict:
    """Создать manifest.json."""
    total_size = sum(f["size"] for f in files_info)
    total_rows = sum(f.get("row_count", 0) for f in files_info)

    manifest = {
        "version": version,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "schema_version": "1.0",
        "files": files_info,
        "total_size": total_size,
        "total_rows": total_rows,
    }

    manifest_path = output_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    return manifest


def find_project_root() -> Path:
    """Найти корневую директорию проекта."""
    current = Path(__file__).resolve().parent

    # Ищем pyproject.toml или .git в родительских директориях
    while current != current.parent:
        if (current / "pyproject.toml").exists() or (current / ".git").exists():
            return current
        current = current.parent

    # Если не нашли, возвращаем директорию скрипта
    return Path(__file__).resolve().parent.parent


def main():
    """Главная функция."""
    parser = argparse.ArgumentParser(description="Генерация данных в формате Parquet")
    parser.add_argument(
        "--version",
        choices=["lite", "full"],
        required=True,
        help="Версия датасета",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Директория для сохранения данных (по умолчанию: <project_root>/data)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Путь к конфигурационному файлу (по умолчанию: <project_root>/configs/scenario_config.yaml)",
    )

    args = parser.parse_args()

    # Найти корень проекта
    project_root = find_project_root()

    # Определить путь к конфигурации
    if args.config is None:
        config_path = project_root / "configs" / "scenario_config.yaml"
    else:
        config_path = Path(args.config).resolve()

    if not config_path.exists():
        print(f"Ошибка: файл конфигурации не найден: {config_path}", file=sys.stderr)
        sys.exit(1)

    # Определить директорию вывода
    if args.output_dir is None:
        output_dir = project_root / "data"
    else:
        output_dir = Path(args.output_dir).resolve()

    # Определить дни для генерации
    if args.version == "lite":
        # Дни 61-74 (14 дней атаки)
        days = list(range(61, 75))
    else:
        # Все 81 день
        days = list(range(1, 82))

    # Инициализировать timeline
    timeline = TimelineEngine(str(config_path))

    # Создать директорию вывода для конкретной версии
    output_dir = output_dir / args.version
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Генерация данных версии '{args.version}' для {len(days)} дней...")

    # Генерировать данные
    files_info = []

    # Auth events
    auth_count = generate_auth_events(timeline, output_dir, days)
    print(f"✓ Сгенерировано {auth_count} событий аутентификации")

    # Nginx logs
    nginx_count = generate_nginx_logs(timeline, output_dir, days)
    print(f"✓ Сгенерировано {nginx_count} веб-логов")

    # DNS queries
    dns_count = generate_dns_queries(timeline, output_dir, days)
    print(f"✓ Сгенерировано {dns_count} DNS-запросов")

    # Firewall events
    firewall_count = generate_firewall_events(timeline, output_dir, days)
    print(f"✓ Сгенерировано {firewall_count} событий фаервола")

    # Собрать информацию о файлах для manifest
    for day in days:
        for data_type in [
            "auth_events",
            "nginx_logs",
            "dns_queries",
            "firewall_events",
        ]:
            day_dir = output_dir / data_type / f"day={day}"
            parquet_file = day_dir / "part-0.parquet"
            if parquet_file.exists():
                file_size = parquet_file.stat().st_size
                # Вычислить checksum
                with open(parquet_file, "rb") as f:
                    sha256 = hashlib.sha256(f.read()).hexdigest()

                files_info.append(
                    {
                        "name": f"{data_type}/day={day}/part-0.parquet",
                        "size": file_size,
                        "sha256": sha256,
                    }
                )

    # Создать manifest
    manifest = create_manifest(output_dir, args.version, files_info)
    print(f"\n✓ Manifest создан: {output_dir / 'manifest.json'}")
    print(f"✓ Всего файлов: {len(files_info)}")
    print(f"✓ Общий размер: {manifest['total_size'] / 1024 / 1024:.2f} MB")


if __name__ == "__main__":
    main()
