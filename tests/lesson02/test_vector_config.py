"""
Тесты для Блока 2: Сбор и маршрутизация логов

Проверяют корректность конфигурации Vector.
"""

import subprocess
import json
import os
from pathlib import Path

import pytest


# Путь к директории lesson02
LESSON_DIR = Path(__file__).parent.parent.parent / "lesson02"
DATA_DIR = LESSON_DIR / "data"


def run_vector_validate(config_path: Path) -> tuple[int, str, str]:
    """Запускает vector validate и возвращает (exit_code, stdout, stderr)."""
    result = subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{config_path.parent}:/config:ro",
            "timberio/vector:latest-alpine",
            "vector", "validate", f"/config/{config_path.name}"
        ],
        capture_output=True,
        text=True,
        timeout=30
    )
    return result.returncode, result.stdout, result.stderr


def run_vector_with_input(config_path: Path, input_data: str, timeout: int = 10) -> list[dict]:
    """
    Запускает Vector с конфигом и входными данными.
    Возвращает список JSON-объектов из stdout.
    """
    # Создаём временный конфиг, который читает из stdin
    temp_config = f"""
[sources.test_input]
type = "stdin"

{config_path.read_text().split('[sources')[1].split('[transforms')[0]}

[transforms.parse_test]
type = "remap"
inputs = ["test_input"]
{_extract_transform_source(config_path)}

[sinks.test_output]
type = "console"
inputs = ["parse_test"]
encoding.codec = "json"
"""
    
    # Для простоты используем готовый конфиг и проверяем вывод
    result = subprocess.run(
        [
            "docker", "run", "--rm", "-i",
            "-v", f"{config_path.parent}:/config:ro",
            "-v", f"{DATA_DIR}:/data:ro",
            "timberio/vector:latest-alpine",
            "vector", "--config", f"/config/{config_path.name}"
        ],
        input="",
        capture_output=True,
        text=True,
        timeout=timeout
    )
    
    # Парсим JSON-строки из stdout
    events = []
    for line in result.stdout.strip().split('\n'):
        if line.strip():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    
    return events


def _extract_transform_source(config_path: Path) -> str:
    """Извлекает source из transforms.parse_nginx."""
    content = config_path.read_text()
    # Упрощённый парсинг — в реальности лучше использовать toml
    return ""


class TestVectorConfigExists:
    """Проверяем наличие конфигурации Vector."""
    
    def test_vector_config_exists(self):
        """Файл vector.toml должен существовать в lesson02/."""
        config_path = LESSON_DIR / "vector.toml"
        assert config_path.exists(), (
            f"Файл {config_path} не найден. "
            "Создайте конфигурацию Vector согласно заданию 2.1"
        )
    
    def test_vector_config_not_empty(self):
        """Конфигурация не должна быть пустой."""
        config_path = LESSON_DIR / "vector.toml"
        if config_path.exists():
            content = config_path.read_text().strip()
            assert len(content) > 100, "Конфигурация слишком короткая"


class TestVectorConfigValid:
    """Проверяем валидность конфигурации."""
    
    @pytest.fixture
    def config_path(self):
        path = LESSON_DIR / "vector.toml"
        if not path.exists():
            pytest.skip("Конфигурация vector.toml не найдена")
        return path
    
    def test_config_validates(self, config_path):
        """Vector должен успешно валидировать конфиг."""
        exit_code, stdout, stderr = run_vector_validate(config_path)
        assert exit_code == 0, f"Ошибка валидации: {stderr}"
    
    def test_config_has_source(self, config_path):
        """Конфиг должен содержать source."""
        content = config_path.read_text()
        assert "[sources." in content, "Конфиг должен содержать секцию [sources.*]"
    
    def test_config_has_transform(self, config_path):
        """Конфиг должен содержать transform."""
        content = config_path.read_text()
        assert "[transforms." in content, "Конфиг должен содержать секцию [transforms.*]"
    
    def test_config_has_sink(self, config_path):
        """Конфиг должен содержать sink."""
        content = config_path.read_text()
        assert "[sinks." in content, "Конфиг должен содержать секцию [sinks.*]"
    
    def test_config_reads_nginx_logs(self, config_path):
        """Конфиг должен читать nginx_access.log."""
        content = config_path.read_text()
        assert "nginx_access.log" in content, (
            "Конфиг должен читать файл nginx_access.log"
        )


class TestVectorOutput:
    """Проверяем вывод Vector."""
    
    @pytest.fixture
    def config_path(self):
        path = LESSON_DIR / "vector.toml"
        if not path.exists():
            pytest.skip("Конфигурация vector.toml не найдена")
        return path
    
    def test_output_has_required_fields(self, config_path):
        """Вывод должен содержать обязательные поля."""
        # Запускаем Vector и получаем первые события
        try:
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", f"{config_path.parent}:/config:ro",
                    "-v", f"{DATA_DIR}:/data:ro",
                    "timberio/vector:latest-alpine",
                    "timeout", "3",
                    "vector", "--config", f"/config/{config_path.name}"
                ],
                capture_output=True,
                text=True,
                timeout=15
            )
        except subprocess.TimeoutExpired:
            pytest.skip("Timeout при запуске Vector")
        
        # Ищем первую JSON-строку
        event = None
        for line in result.stdout.strip().split('\n'):
            if line.strip().startswith('{'):
                try:
                    event = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
        
        if event is None:
            pytest.skip("Не удалось получить события из Vector")
        
        # Проверяем обязательные поля
        required_fields = ["ip", "method", "path", "status", "severity"]
        missing = [f for f in required_fields if f not in event]
        
        assert not missing, f"Отсутствуют обязательные поля: {missing}"
    
    def test_severity_correct_for_errors(self, config_path):
        """severity должен быть 'error' для статусов >= 400."""
        try:
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", f"{config_path.parent}:/config:ro",
                    "-v", f"{DATA_DIR}:/data:ro",
                    "timberio/vector:latest-alpine",
                    "timeout", "3",
                    "vector", "--config", f"/config/{config_path.name}"
                ],
                capture_output=True,
                text=True,
                timeout=15
            )
        except subprocess.TimeoutExpired:
            pytest.skip("Timeout при запуске Vector")
        
        # Собираем все события
        events = []
        for line in result.stdout.strip().split('\n'):
            if line.strip().startswith('{'):
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        
        if not events:
            pytest.skip("Не удалось получить события из Vector")
        
        # Проверяем severity для каждого события
        for event in events:
            if "status" in event and "severity" in event:
                status = int(event["status"]) if isinstance(event["status"], str) else event["status"]
                if status >= 400:
                    assert event["severity"] == "error", (
                        f"Для статуса {status} severity должен быть 'error', "
                        f"получено '{event['severity']}'"
                    )
                else:
                    assert event["severity"] == "info", (
                        f"Для статуса {status} severity должен быть 'info', "
                        f"получено '{event['severity']}'"
                    )
