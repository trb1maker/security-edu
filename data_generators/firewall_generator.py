"""
Генератор событий фаервола в формате syslog/CEF.

Формат CEF:
timestamp hostname CEF:0|FinanceFlow|Firewall|1.0|event_id|action|severity|src=... dst=... spt=... dpt=... proto=... act=... reason=...
"""

from datetime import datetime, timedelta
from typing import Any

from data_generators.scenario_controller import (
    AttackPhase,
    AttackPhases,
    TimelineEngine,
)


class FirewallGenerator:
    """Генератор событий фаервола."""

    PROTOCOLS = ["TCP", "UDP", "ICMP"]
    COMMON_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443]
    SUSPICIOUS_PORTS = [4444, 5555, 6666, 9999, 31337]

    def __init__(self, timeline: TimelineEngine):
        self.timeline = timeline
        self.hostname = "fw-gateway"

    def generate_day(self, day: int) -> list[dict[str, Any]]:
        """Генерировать события за один день."""
        events = []
        rng = self.timeline.get_random("firewall", day)
        phase, intensity = self.timeline.get_phase_for_day(day)

        # Определить количество событий
        base_events = self.timeline.config["generators"]["firewall"][
            "events_per_day_normal"
        ]
        if self.timeline.is_attack_day(day):
            base_events = self.timeline.config["generators"]["firewall"][
                "events_per_day_attack"
            ]

        multiplier = AttackPhases.get_events_multiplier(phase, intensity)
        num_events = int(base_events * multiplier)

        date = self.timeline.get_date_for_day(day)

        # Распределение событий в течение дня
        # 80% событий в рабочее время (6:00 - 22:00), 20% вне рабочего времени
        work_hours = list(range(6, 23))  # 17 часов рабочего времени
        off_hours = list(range(0, 6)) + [23]  # 7 часов нерабочего времени

        for i in range(num_events):
            # Выбрать час с учетом рабочего/нерабочего времени
            if rng.random() < 0.8:  # 80% вероятность рабочего времени
                hour = rng.choice(work_hours)
            else:  # 20% вероятность нерабочего времени
                hour = rng.choice(off_hours)

            timestamp = date + timedelta(
                hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59)
            )

            # Определить тип события
            if AttackPhases.should_generate_attack_event(phase, intensity, rng):
                event = self._generate_attack_event(phase, intensity, timestamp, rng)
            else:
                event = self._generate_normal_event(timestamp, rng)

            events.append(event)

        return sorted(events, key=lambda x: x["timestamp"])

    def _generate_normal_event(self, timestamp: datetime, rng) -> dict[str, Any]:
        """Генерировать нормальное событие фаервола."""
        source_ip = rng.choice(self.timeline.get_internal_ips())
        dest_ip = rng.choice(self.timeline.get_external_ips())
        protocol = rng.choice(self.PROTOCOLS)

        # Большинство событий - разрешенные соединения
        if rng.random() < 0.9:
            action = "ALLOW"
            dest_port = rng.choice([80, 443, 53])  # HTTP, HTTPS, DNS
        else:
            action = "BLOCK"
            dest_port = rng.choice(self.COMMON_PORTS)

        source_port = rng.randint(32768, 65535)

        if protocol == "TCP":
            bytes_sent = rng.randint(100, 10000)
            bytes_received = rng.randint(100, 10000)
        elif protocol == "UDP":
            bytes_sent = rng.randint(50, 500)
            bytes_received = rng.randint(50, 500)
        else:  # ICMP
            bytes_sent = rng.randint(50, 200)
            bytes_received = rng.randint(50, 200)

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "source_port": source_port,
            "dest_port": dest_port,
            "protocol": protocol,
            "action": action,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "reason": "policy" if action == "ALLOW" else "unauthorized_port",
        }

    def _generate_attack_event(
        self, phase: AttackPhase, intensity: float, timestamp: datetime, rng
    ) -> dict[str, Any]:
        """Генерировать событие атаки."""
        attacker_ips = self.timeline.get_attacker_ips()
        internal_ips = self.timeline.get_internal_ips()

        if phase == AttackPhase.RECON:
            # Сканирование портов - множество блокированных соединений
            source_ip = rng.choice(attacker_ips)
            dest_ip = rng.choice(internal_ips)
            dest_port = rng.choice(self.COMMON_PORTS + self.SUSPICIOUS_PORTS)
            protocol = "TCP"
            action = "BLOCK"
            source_port = rng.randint(40000, 50000)
            bytes_sent = rng.randint(60, 100)
            bytes_received = 0
            reason = "port_scan"

        elif phase == AttackPhase.BRUTEFORCE:
            # Попытки подключения к SSH
            source_ip = rng.choice(attacker_ips)
            dest_ip = rng.choice(internal_ips)
            dest_port = 22
            protocol = "TCP"
            action = "BLOCK"
            source_port = rng.randint(40000, 50000)
            bytes_sent = rng.randint(60, 100)
            bytes_received = 0
            reason = "brute_force_attempt"

        elif phase == AttackPhase.LATERAL:
            # Перемещение по сети - разрешенные соединения между внутренними IP
            source_ip = rng.choice(internal_ips)
            dest_ip = rng.choice([ip for ip in internal_ips if ip != source_ip])
            dest_port = rng.choice([3306, 5432, 6379])  # Порты БД
            protocol = "TCP"
            action = "ALLOW"
            source_port = rng.randint(32768, 65535)
            bytes_sent = rng.randint(1000, 100000)
            bytes_received = rng.randint(1000, 100000)
            reason = "policy"

        elif phase == AttackPhase.EXFIL:
            # Exfiltration - исходящий трафик на нестандартные порты
            source_ip = rng.choice(internal_ips)
            dest_ip = rng.choice(attacker_ips)
            dest_port = rng.choice([443, 8443, 4444])
            protocol = "TCP"
            action = "ALLOW"  # Может быть пропущен
            source_port = rng.randint(32768, 65535)
            bytes_sent = rng.randint(1000000, 10000000)  # Большой объем данных
            bytes_received = rng.randint(1000, 10000)
            reason = "policy"

        else:
            # Для других фаз генерируем нормальное событие
            return self._generate_normal_event(timestamp, rng)

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "source_port": source_port,
            "dest_port": dest_port,
            "protocol": protocol,
            "action": action,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "reason": reason,
        }

    def format_log_line(self, event: dict[str, Any]) -> str:
        """Форматировать событие в формат CEF."""
        timestamp_str = event["timestamp"].strftime("%b %d %H:%M:%S")
        event_id = 100 if event["action"] == "ALLOW" else 200
        severity = 3 if event["action"] == "ALLOW" else 7

        return (
            f"{timestamp_str} {self.hostname} CEF:0|FinanceFlow|Firewall|1.0|{event_id}|"
            f"Connection {event['action'].lower()}|{severity}|"
            f"src={event['source_ip']} dst={event['dest_ip']} "
            f"spt={event['source_port']} dpt={event['dest_port']} "
            f"proto={event['protocol']} act={event['action'].lower()} "
            f"reason={event['reason']}"
        )
