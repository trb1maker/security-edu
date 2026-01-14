"""
Генератор событий аутентификации.

Генерирует события в формате JSON:
- login_success: успешный вход
- login_failure: неудачная попытка входа
- logout: выход из системы
"""

from datetime import datetime, timedelta
from typing import Any

from data_generators.scenario_controller import (
    AttackPhase,
    AttackPhases,
    TimelineEngine,
)


class AuthGenerator:
    """Генератор событий аутентификации."""

    AUTH_METHODS = ["password", "ssh_key", "certificate", "2fa"]
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "curl/7.68.0",
        "python-requests/2.28.0",
        "OpenSSH_8.2p1",
    ]

    def __init__(self, timeline: TimelineEngine):
        self.timeline = timeline

    def generate_day(self, day: int) -> list[dict[str, Any]]:
        """Генерировать события за один день."""
        events = []
        rng = self.timeline.get_random("auth", day)
        phase, intensity = self.timeline.get_phase_for_day(day)

        # Определить количество событий
        base_events = self.timeline.config["generators"]["auth"][
            "events_per_day_normal"
        ]
        if self.timeline.is_attack_day(day):
            base_events = self.timeline.config["generators"]["auth"][
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
                hours=hour,
                minutes=rng.randint(0, 59),
                seconds=rng.randint(0, 59),
                microseconds=rng.randint(0, 999999),
            )

            # Определить тип события
            if AttackPhases.should_generate_attack_event(phase, intensity, rng):
                event = self._generate_attack_event(phase, intensity, timestamp, rng)
            else:
                event = self._generate_normal_event(timestamp, rng)

            events.append(event)

        return sorted(events, key=lambda x: x["timestamp"])

    def _generate_normal_event(self, timestamp: datetime, rng) -> dict[str, Any]:
        """Генерировать нормальное событие."""
        username = rng.choice(self.timeline.get_normal_users())
        source_ip = rng.choice(self.timeline.get_internal_ips())

        # Вероятности для нормальной активности
        event_weights = {"login_success": 0.6, "logout": 0.3, "login_failure": 0.1}

        event_type = rng.choices(
            list(event_weights.keys()), weights=list(event_weights.values())
        )[0]

        details = {
            "method": rng.choice(self.AUTH_METHODS),
            "user_agent": rng.choice(self.USER_AGENTS),
        }

        if event_type == "login_failure":
            details["reason"] = rng.choice(["invalid_password", "expired_password"])
            details["attempt"] = rng.randint(1, 2)
        elif event_type == "logout":
            details["session_duration_minutes"] = rng.randint(5, 480)

        return {
            "timestamp": timestamp.isoformat() + "Z",
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip,
            "success": event_type == "login_success",
            "details": details,
        }

    def _generate_attack_event(
        self, phase: AttackPhase, intensity: float, timestamp: datetime, rng
    ) -> dict[str, Any]:
        """Генерировать событие атаки."""
        attacker_ips = self.timeline.get_attacker_ips()
        target_user = self.timeline.get_target_user()

        if phase == AttackPhase.BRUTEFORCE:
            # Массовые неудачные попытки входа
            return {
                "timestamp": timestamp.isoformat() + "Z",
                "event_type": "login_failure",
                "username": target_user,
                "source_ip": rng.choice(attacker_ips),
                "success": False,
                "details": {
                    "method": "password",
                    "reason": rng.choice(["invalid_password", "user_not_found"]),
                    "attempt": rng.randint(5, 50),
                    "user_agent": "python-requests/2.28.0",
                },
            }

        elif phase == AttackPhase.COMPROMISE:
            # Успешный вход после серии неудач
            return {
                "timestamp": timestamp.isoformat() + "Z",
                "event_type": "login_success",
                "username": target_user,
                "source_ip": rng.choice(attacker_ips),
                "success": True,
                "details": {
                    "method": "password",
                    "user_agent": "python-requests/2.28.0",
                    "suspicious": True,
                },
            }

        elif phase == AttackPhase.LATERAL:
            # Перемещение по сети - входы с разных внутренних IP
            internal_ips = self.timeline.get_internal_ips()
            return {
                "timestamp": timestamp.isoformat() + "Z",
                "event_type": "login_success",
                "username": target_user,
                "source_ip": rng.choice(internal_ips),
                "success": True,
                "details": {
                    "method": "ssh_key",
                    "user_agent": "OpenSSH_8.2p1",
                    "suspicious": True,
                },
            }

        else:
            # Для других фаз генерируем нормальное событие
            return self._generate_normal_event(timestamp, rng)
