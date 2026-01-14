"""
Центральный контроллер сценария атаки.

Управляет таймлайном, интенсивностью событий и обеспечивает детерминированность
через фиксированные seed-значения.
"""

import random
from datetime import datetime, timedelta
from enum import Enum

import yaml


class AttackPhase(Enum):
    """Этапы атаки."""

    BASELINE = "BASELINE"
    RECON = "RECON"
    BRUTEFORCE = "BRUTEFORCE"
    COMPROMISE = "COMPROMISE"
    LATERAL = "LATERAL"
    C2_SETUP = "C2_SETUP"
    EXFIL = "EXFIL"
    POST_INCIDENT = "POST_INCIDENT"


class SeedManager:
    """Управление seed-значениями для детерминированной генерации."""

    def __init__(self, base_seed: int):
        self.base_seed = base_seed
        self._generators = {}

    def get_generator(self, name: str, day: int) -> random.Random:
        """Получить генератор случайных чисел для конкретного генератора и дня."""
        key = f"{name}_{day}"
        if key not in self._generators:
            seed = self.base_seed + hash(key) % (2**31)
            self._generators[key] = random.Random(seed)
        return self._generators[key]

    def reset(self):
        """Сбросить все генераторы."""
        self._generators.clear()


class TimelineEngine:
    """Движок временной линии для управления сценарием."""

    def __init__(self, config_path: str):
        with open(config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)

        self.scenario = self.config["scenario"]
        self.start_date = datetime.fromisoformat(self.scenario["start_date"])
        self.duration_days = self.scenario["duration_days"]
        self.attack_start_day = self.scenario["attack_params"]["attack_start_day"]
        self.attack_timeline = self.config["attack_timeline"]

        self.seed_manager = SeedManager(self.scenario["base_seed"])

    def get_date_for_day(self, day: int) -> datetime:
        """Получить дату для конкретного дня."""
        return self.start_date + timedelta(days=day - 1)

    def get_phase_for_day(self, day: int) -> tuple[AttackPhase, float]:
        """
        Получить фазу атаки и интенсивность для конкретного дня.

        Returns:
            (phase, intensity) где intensity от 0.0 до 1.0
        """
        if day < self.attack_start_day:
            return (AttackPhase.BASELINE, 0.0)

        if day > self.attack_start_day + 14:
            return (AttackPhase.POST_INCIDENT, 0.0)

        attack_day = day - self.attack_start_day + 1
        if attack_day in self.attack_timeline:
            phase_data = self.attack_timeline[attack_day]
            phase = AttackPhase[phase_data["phase"]]
            intensity = phase_data["intensity"]
            return (phase, intensity)

        return (AttackPhase.BASELINE, 0.0)

    def is_attack_day(self, day: int) -> bool:
        """Проверить, является ли день частью атаки."""
        return self.attack_start_day <= day <= self.attack_start_day + 14

    def get_random(self, generator_name: str, day: int) -> random.Random:
        """Получить детерминированный генератор случайных чисел."""
        return self.seed_manager.get_generator(generator_name, day)

    def get_attacker_ips(self) -> list[str]:
        """Получить список IP-адресов атакующего."""
        return self.scenario["attack_params"]["attacker_ips"]

    def get_target_user(self) -> str:
        """Получить имя целевого пользователя."""
        return self.scenario["attack_params"]["target_user"]

    def get_c2_domain(self) -> str:
        """Получить домен C2."""
        return self.scenario["attack_params"]["c2_domain"]

    def get_normal_users(self) -> list[str]:
        """Получить список нормальных пользователей."""
        return self.scenario["normal_traffic"]["users"]

    def get_internal_ips(self) -> list[str]:
        """Получить список внутренних IP-адресов."""
        return self.scenario["normal_traffic"]["internal_ips"]

    def get_external_ips(self) -> list[str]:
        """Получить список внешних IP-адресов."""
        return self.scenario["normal_traffic"].get("external_ips", [])


class AttackPhases:
    """Утилиты для работы с фазами атаки."""

    @staticmethod
    def should_generate_attack_event(
        phase: AttackPhase, intensity: float, rng: random.Random
    ) -> bool:
        """Определить, нужно ли генерировать событие атаки."""
        if phase == AttackPhase.BASELINE:
            return False
        return rng.random() < intensity

    @staticmethod
    def get_events_multiplier(phase: AttackPhase, intensity: float) -> float:
        """Получить множитель количества событий для фазы."""
        if phase == AttackPhase.BASELINE:
            return 1.0
        return 1.0 + intensity * 0.6  # От 1.0 до 1.6
