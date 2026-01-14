"""
Генератор DNS-запросов в формате BIND query log.

Формат:
timestamp client @0x... source_ip#port (domain): query: domain IN TYPE +flags (resolver)
"""

import string
from datetime import datetime, timedelta
from typing import Any

from data_generators.scenario_controller import (
    AttackPhase,
    AttackPhases,
    TimelineEngine,
)


class DnsGenerator:
    """Генератор DNS-запросов."""

    QUERY_TYPES = ["A", "AAAA", "TXT", "MX", "NS", "CNAME"]
    NORMAL_DOMAINS = [
        "google.com",
        "yandex.ru",
        "github.com",
        "stackoverflow.com",
        "financeflow.com",
        "api.financeflow.com",
        "cdn.financeflow.com",
        "mail.financeflow.com",
    ]

    def __init__(self, timeline: TimelineEngine):
        self.timeline = timeline

    def generate_day(self, day: int) -> list[dict[str, Any]]:
        """Генерировать запросы за один день."""
        queries = []
        rng = self.timeline.get_random("dns", day)
        phase, intensity = self.timeline.get_phase_for_day(day)

        # Определить количество запросов
        base_queries = self.timeline.config["generators"]["dns"][
            "queries_per_day_normal"
        ]
        if self.timeline.is_attack_day(day):
            base_queries = self.timeline.config["generators"]["dns"][
                "queries_per_day_attack"
            ]

        multiplier = AttackPhases.get_events_multiplier(phase, intensity)
        num_queries = int(base_queries * multiplier)

        date = self.timeline.get_date_for_day(day)

        # Распределение запросов в течение дня
        # 80% запросов в рабочее время (6:00 - 22:00), 20% вне рабочего времени
        work_hours = list(range(6, 23))  # 17 часов рабочего времени
        off_hours = list(range(0, 6)) + [23]  # 7 часов нерабочего времени

        for i in range(num_queries):
            # Выбрать час с учетом рабочего/нерабочего времени
            if rng.random() < 0.8:  # 80% вероятность рабочего времени
                hour = rng.choice(work_hours)
            else:  # 20% вероятность нерабочего времени
                hour = rng.choice(off_hours)

            timestamp = date + timedelta(
                hours=hour,
                minutes=rng.randint(0, 59),
                seconds=rng.randint(0, 59),
                milliseconds=rng.randint(0, 999),
            )

            # Определить тип запроса
            if AttackPhases.should_generate_attack_event(phase, intensity, rng):
                query = self._generate_attack_query(phase, intensity, timestamp, rng)
            else:
                query = self._generate_normal_query(timestamp, rng)

            queries.append(query)

        return sorted(queries, key=lambda x: x["timestamp"])

    def _generate_normal_query(self, timestamp: datetime, rng) -> dict[str, Any]:
        """Генерировать нормальный DNS-запрос."""
        source_ip = rng.choice(self.timeline.get_internal_ips())
        domain = rng.choice(self.NORMAL_DOMAINS)
        query_type = rng.choice(self.QUERY_TYPES)
        resolver = "192.168.1.1"  # Внутренний DNS-резолвер

        # Ответы для нормальных доменов
        if domain.endswith("financeflow.com"):
            resolved_ip = rng.choice(["192.168.1.10", "192.168.1.11"])
            response_code = "NOERROR"
        else:
            resolved_ip = None  # Внешние домены не резолвятся в нашем контексте
            response_code = "NOERROR"

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "source_port": rng.randint(50000, 65535),
            "query_domain": domain,
            "query_type": query_type,
            "response_code": response_code,
            "resolved_ip": resolved_ip,
            "resolver": resolver,
        }

    def _generate_attack_query(
        self, phase: AttackPhase, intensity: float, timestamp: datetime, rng
    ) -> dict[str, Any]:
        """Генерировать DNS-запрос атаки."""
        c2_domain = self.timeline.get_c2_domain()

        if phase == AttackPhase.C2_SETUP or phase == AttackPhase.EXFIL:
            # DGA-поддомены для C2
            source_ip = rng.choice(self.timeline.get_internal_ips())

            # Генерировать случайный поддомен (DGA-паттерн)
            subdomain_length = rng.randint(8, 16)
            subdomain = "".join(
                rng.choice(string.ascii_lowercase + string.digits)
                for _ in range(subdomain_length)
            )
            domain = f"{subdomain}.{c2_domain}"

            query_type = rng.choice(["A", "TXT"])
            resolver = "8.8.8.8"  # Внешний резолвер для C2

            # C2-домены могут резолвиться в IP атакующего
            if rng.random() < 0.3:  # 30% успешных резолвов
                attacker_ips = self.timeline.get_attacker_ips()
                resolved_ip = rng.choice(attacker_ips)
            else:
                resolved_ip = None

            response_code = "NOERROR"

        else:
            # Для других фаз генерируем нормальный запрос
            return self._generate_normal_query(timestamp, rng)

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "source_port": rng.randint(50000, 65535),
            "query_domain": domain,
            "query_type": query_type,
            "response_code": response_code,
            "resolved_ip": resolved_ip,
            "resolver": resolver,
        }

    def format_log_line(self, query: dict[str, Any]) -> str:
        """Форматировать запрос в формат BIND query log."""
        timestamp_str = query["timestamp"].strftime("%d-%b-%Y %H:%M:%S.%f")[:-3]
        client_id = f"@0x{hash(query['source_ip'] + str(query['timestamp'])):016x}"

        flags = "+E(0)K"
        resolver_part = f" ({query['resolver']})" if query.get("resolver") else ""

        return (
            f"{timestamp_str} client {client_id} "
            f"{query['source_ip']}#{query['source_port']} "
            f"({query['query_domain']}): query: {query['query_domain']} "
            f"IN {query['query_type']} {flags}{resolver_part}"
        )
