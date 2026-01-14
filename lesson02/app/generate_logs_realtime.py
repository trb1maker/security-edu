"""
Скрипт для real-time генерации логов из различных источников.

Генерирует логи в реальном времени и записывает их в файлы для последующей обработки Vector.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Добавляем корень проекта в путь для импорта генераторов
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from data_generators.auth_generator import AuthGenerator
from data_generators.dns_generator import DnsGenerator
from data_generators.firewall_generator import FirewallGenerator
from data_generators.nginx_generator import NginxGenerator
from data_generators.scenario_controller import TimelineEngine


def generate_logs_realtime(
    config_path: Path,
    output_dir: Path,
    start_day: int = 61,
    speed_multiplier: float = 1.0,
    duration_hours: float = 24.0,
):
    """
    Генерировать логи в реальном времени.

    Args:
        config_path: Путь к конфигурации сценария
        output_dir: Директория для записи логов
        start_day: С какого дня начать генерацию (по умолчанию 61 - начало атаки)
        speed_multiplier: Множитель скорости (1.0 = реальное время, 60.0 = минута в секунду)
        duration_hours: Продолжительность генерации в часах
    """
    # Создать директорию для логов
    output_dir.mkdir(parents=True, exist_ok=True)

    # Инициализировать TimelineEngine
    timeline = TimelineEngine(str(config_path))

    # Инициализировать генераторы
    auth_gen = AuthGenerator(timeline)
    nginx_gen = NginxGenerator(timeline)
    dns_gen = DnsGenerator(timeline)
    firewall_gen = FirewallGenerator(timeline)

    # Открыть файлы для записи логов
    auth_file = (output_dir / "auth_events.log").open("w", encoding="utf-8")
    nginx_file = (output_dir / "nginx_logs.log").open("w", encoding="utf-8")
    dns_file = (output_dir / "dns_queries.log").open("w", encoding="utf-8")
    firewall_file = (output_dir / "firewall_events.log").open("w", encoding="utf-8")

    try:
        # Получить дату начала и привести к UTC timezone
        start_date = timeline.get_date_for_day(start_day)
        if start_date.tzinfo is None:
            start_date = start_date.replace(tzinfo=timezone.utc)
        end_date = start_date + timedelta(hours=duration_hours)

        print(f"Начало генерации: {start_date}")
        print(f"Конец генерации: {end_date}")
        print(f"Скорость: {speed_multiplier}x")
        print(f"Логи записываются в: {output_dir}")

        # Определить количество дней для генерации
        num_days = int(duration_hours / 24) + 1

        # Собрать все события за нужные дни
        all_events = []

        for day_offset in range(num_days):
            day = start_day + day_offset
            if day > timeline.scenario["duration_days"]:
                break

            print(f"Генерация событий для дня {day}...")

            # Генерировать события за день
            day_auth = auth_gen.generate_day(day)
            day_nginx = nginx_gen.generate_day(day)
            day_dns = dns_gen.generate_day(day)
            day_firewall = firewall_gen.generate_day(day)

            # Преобразовать в единый формат с временными метками
            for event in day_auth:
                event_time = datetime.fromisoformat(
                    event["timestamp"].replace("Z", "+00:00")
                )
                if start_date <= event_time < end_date:
                    all_events.append(
                        (
                            event_time,
                            "auth",
                            event,
                            auth_gen,
                            auth_file,
                        )
                    )

            for log_entry in day_nginx:
                event_time = log_entry["timestamp"]
                if event_time.tzinfo is None:
                    event_time = event_time.replace(tzinfo=timezone.utc)
                if start_date <= event_time < end_date:
                    all_events.append(
                        (
                            event_time,
                            "nginx",
                            log_entry,
                            nginx_gen,
                            nginx_file,
                        )
                    )

            for query in day_dns:
                event_time = query["timestamp"]
                if event_time.tzinfo is None:
                    event_time = event_time.replace(tzinfo=timezone.utc)
                if start_date <= event_time < end_date:
                    all_events.append(
                        (
                            event_time,
                            "dns",
                            query,
                            dns_gen,
                            dns_file,
                        )
                    )

            for event in day_firewall:
                event_time = event["timestamp"]
                if event_time.tzinfo is None:
                    event_time = event_time.replace(tzinfo=timezone.utc)
                if start_date <= event_time < end_date:
                    all_events.append(
                        (
                            event_time,
                            "firewall",
                            event,
                            firewall_gen,
                            firewall_file,
                        )
                    )

        # Сортировать все события по времени
        all_events.sort(key=lambda x: x[0])

        print(f"Всего событий для генерации: {len(all_events)}")
        print("Начало выдачи событий в реальном времени...")

        # Выдавать события в реальном времени
        start_real_time = time.time()
        start_event_time = all_events[0][0] if all_events else start_date

        for event_time, event_type, event_data, generator, file in all_events:
            # Вычислить задержку до этого события
            time_delta = (event_time - start_event_time).total_seconds()
            real_time_delta = time_delta / speed_multiplier

            # Подождать нужное время
            elapsed = time.time() - start_real_time
            sleep_time = real_time_delta - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

            # Записать событие
            if hasattr(generator, "format_log_line"):
                log_line = generator.format_log_line(event_data)
                file.write(log_line + "\n")
            else:
                file.write(json.dumps(event_data, ensure_ascii=False) + "\n")
            file.flush()

    except KeyboardInterrupt:
        print("\nОстановка генерации...")
    finally:
        # Закрыть файлы
        auth_file.close()
        nginx_file.close()
        dns_file.close()
        firewall_file.close()

        print(f"\nГенерация завершена. Логи сохранены в {output_dir}")




def main():
    """Главная функция."""
    parser = argparse.ArgumentParser(
        description="Генерация логов в реальном времени для Vector"
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/scenario_config.yaml"),
        help="Путь к конфигурации сценария",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/logs"),
        help="Директория для записи логов",
    )
    parser.add_argument(
        "--start-day",
        type=int,
        default=61,
        help="День начала генерации (по умолчанию 61 - начало атаки)",
    )
    parser.add_argument(
        "--speed",
        type=float,
        default=60.0,
        help="Множитель скорости генерации (по умолчанию 60 - минута в секунду)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=1.0,
        help="Продолжительность генерации в часах (по умолчанию 1 час)",
    )

    args = parser.parse_args()

    # Найти конфигурацию относительно корня проекта
    if not args.config.is_absolute():
        # В контейнере WORKDIR = /app, локально - ищем pyproject.toml
        if Path("/app").exists() and (Path("/app") / "pyproject.toml").exists():
            project_root = Path("/app")
        else:
            # Локальный запуск - ищем корень проекта
            current = Path(__file__).resolve().parent
            while current != current.parent:
                if (current / "pyproject.toml").exists():
                    project_root = current
                    break
                current = current.parent
            else:
                # Если не нашли, используем директорию скрипта как корень
                project_root = Path(__file__).resolve().parent
        
        config_path = project_root / args.config
    else:
        config_path = args.config

    if not config_path.exists():
        print(f"Ошибка: файл конфигурации {config_path} не найден")
        sys.exit(1)

    generate_logs_realtime(
        config_path=config_path,
        output_dir=args.output_dir,
        start_day=args.start_day,
        speed_multiplier=args.speed,
        duration_hours=args.duration,
    )


if __name__ == "__main__":
    main()
