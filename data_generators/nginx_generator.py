"""
Генератор веб-логов nginx в формате Combined Log Format.

Формат:
IP - - [timestamp] "METHOD path HTTP/1.1" status size "referer" "user-agent"
"""

from datetime import datetime, timedelta
from typing import Any

from data_generators.scenario_controller import (
    AttackPhase,
    AttackPhases,
    TimelineEngine,
)


class NginxGenerator:
    """Генератор веб-логов nginx."""

    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
    NORMAL_PATHS = [
        "/",
        "/index.html",
        "/api/v1/status",
        "/api/v1/payment",
        "/api/v1/users",
        "/dashboard",
        "/login",
        "/logout",
        "/checkout",
        "/products",
        "/about",
    ]
    SUSPICIOUS_PATHS = [
        "/admin",
        "/wp-admin",
        "/.env",
        "/.git/config",
        "/phpmyadmin",
        "/administrator",
        "/.well-known",
        "/api/v1/admin",
    ]

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
        "curl/7.68.0",
    ]

    REFERERS = [
        "-",
        "https://financeflow.com/",
        "https://financeflow.com/checkout",
        "https://google.com/",
    ]

    def __init__(self, timeline: TimelineEngine):
        self.timeline = timeline

    def generate_day(self, day: int) -> list[dict[str, Any]]:
        """Генерировать логи за один день."""
        logs = []
        rng = self.timeline.get_random("nginx", day)
        phase, intensity = self.timeline.get_phase_for_day(day)

        # Определить количество запросов
        base_requests = self.timeline.config["generators"]["nginx"][
            "requests_per_day_normal"
        ]
        if self.timeline.is_attack_day(day):
            base_requests = self.timeline.config["generators"]["nginx"][
                "requests_per_day_attack"
            ]

        multiplier = AttackPhases.get_events_multiplier(phase, intensity)
        num_requests = int(base_requests * multiplier)

        date = self.timeline.get_date_for_day(day)

        # Распределение запросов в течение дня
        # 80% запросов в рабочее время (6:00 - 22:00), 20% вне рабочего времени
        work_hours = list(range(6, 23))  # 17 часов рабочего времени
        off_hours = list(range(0, 6)) + [23]  # 7 часов нерабочего времени

        for i in range(num_requests):
            # Выбрать час с учетом рабочего/нерабочего времени
            if rng.random() < 0.8:  # 80% вероятность рабочего времени
                hour = rng.choice(work_hours)
            else:  # 20% вероятность нерабочего времени
                hour = rng.choice(off_hours)

            timestamp = date + timedelta(
                hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59)
            )

            # Определить тип запроса
            if AttackPhases.should_generate_attack_event(phase, intensity, rng):
                log_entry = self._generate_attack_request(
                    phase, intensity, timestamp, rng
                )
            else:
                log_entry = self._generate_normal_request(timestamp, rng)

            logs.append(log_entry)

        return sorted(logs, key=lambda x: x["timestamp"])

    def _generate_normal_request(self, timestamp: datetime, rng) -> dict[str, Any]:
        """Генерировать нормальный запрос."""
        source_ip = rng.choice(
            self.timeline.get_internal_ips() + self.timeline.get_external_ips()
        )
        method = rng.choice(self.HTTP_METHODS)
        path = rng.choice(self.NORMAL_PATHS)

        # Вероятности статусов для нормальных запросов
        status_weights = {
            200: 0.85,
            201: 0.05,
            301: 0.03,
            302: 0.02,
            400: 0.02,
            404: 0.02,
            500: 0.01,
        }

        status = rng.choices(
            list(status_weights.keys()), weights=list(status_weights.values())
        )[0]

        # Размер ответа зависит от статуса и пути
        if status == 200:
            if path.startswith("/api/"):
                size = rng.randint(100, 5000)
            else:
                size = rng.randint(1000, 50000)
        elif status in [301, 302]:
            size = rng.randint(200, 500)
        else:
            size = rng.randint(100, 2000)

        user_agent = rng.choice(self.USER_AGENTS)
        referer = rng.choice(self.REFERERS)

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "method": method,
            "path": path,
            "status": status,
            "size": size,
            "referer": referer,
            "user_agent": user_agent,
        }

    def _generate_attack_request(
        self, phase: AttackPhase, intensity: float, timestamp: datetime, rng
    ) -> dict[str, Any]:
        """Генерировать запрос атаки."""
        attacker_ips = self.timeline.get_attacker_ips()

        if phase == AttackPhase.RECON:
            # Сканирование - запросы к подозрительным путям
            source_ip = rng.choice(attacker_ips)
            path = rng.choice(self.SUSPICIOUS_PATHS)
            method = "GET"
            status = rng.choice([403, 404])
            size = rng.randint(100, 500)
            user_agent = "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
            referer = "-"

        elif phase == AttackPhase.BRUTEFORCE:
            # Brute-force на /login
            source_ip = rng.choice(attacker_ips)
            path = "/login"
            method = "POST"
            status = 401
            size = rng.randint(100, 500)
            user_agent = "python-requests/2.28.0"
            referer = "-"

        elif phase == AttackPhase.EXFIL:
            # Exfiltration - необычно большие ответы
            source_ip = rng.choice(self.timeline.get_internal_ips())
            path = rng.choice(["/api/v1/payment", "/api/v1/users"])
            method = "GET"
            status = 200
            size = rng.randint(1000000, 5000000)  # 1-5 MB
            user_agent = rng.choice(self.USER_AGENTS)
            referer = "-"

        else:
            # Для других фаз генерируем нормальный запрос
            return self._generate_normal_request(timestamp, rng)

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "method": method,
            "path": path,
            "status": status,
            "size": size,
            "referer": referer,
            "user_agent": user_agent,
        }

    def format_log_line(self, log_entry: dict[str, Any]) -> str:
        """Форматировать запись в Combined Log Format."""
        timestamp_str = log_entry["timestamp"].strftime("%d/%b/%Y:%H:%M:%S +0000")
        return (
            f"{log_entry['source_ip']} - - [{timestamp_str}] "
            f'"{log_entry["method"]} {log_entry["path"]} HTTP/1.1" '
            f"{log_entry['status']} {log_entry['size']} "
            f'"{log_entry["referer"]}" "{log_entry["user_agent"]}"'
        )
