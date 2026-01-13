"""
Тесты для Блока 5: Python для обработки данных

Проверяет:
- Корректность функции энтропии
- Работу с IP-адресами
- Feature engineering
"""

import os
import math
from collections import Counter
import pytest


def shannon_entropy(s: str) -> float:
    """Референсная реализация энтропии Шеннона."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class TestEntropyFunction:
    """Тесты для функции энтропии."""

    def test_empty_string(self):
        """Энтропия пустой строки должна быть 0."""
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        """Энтропия строки из одного символа должна быть 0."""
        assert shannon_entropy("aaaaaa") == 0.0

    def test_uniform_distribution(self):
        """Энтропия равномерного распределения должна быть максимальной."""
        # Для 4 символов максимальная энтропия = log2(4) = 2
        entropy = shannon_entropy("abcd")
        assert abs(entropy - 2.0) < 0.01

    def test_dga_like_string(self):
        """DGA-подобные строки должны иметь высокую энтропию."""
        entropy = shannon_entropy("x7kj2m9p")
        assert entropy > 2.5, f"Ожидалась высокая энтропия, получено {entropy}"

    def test_normal_domain(self):
        """Обычные слова должны иметь умеренную энтропию."""
        entropy = shannon_entropy("google")
        assert entropy < 2.5, f"Ожидалась умеренная энтропия, получено {entropy}"


class TestIPProcessing:
    """Тесты для работы с IP-адресами."""

    def test_private_ip_detection(self):
        """Проверяет определение приватных IP."""
        import ipaddress
        
        private_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
        public_ips = ["8.8.8.8", "1.1.1.1"]
        
        for ip in private_ips:
            assert ipaddress.ip_address(ip).is_private, f"{ip} должен быть приватным"
        
        for ip in public_ips:
            assert not ipaddress.ip_address(ip).is_private, f"{ip} не должен быть приватным"


class TestPolarsIntegration:
    """Тесты для интеграции с Polars."""

    def test_polars_import(self):
        """Проверяет, что polars установлен."""
        import polars as pl
        assert pl is not None

    def test_parquet_reading(self):
        """Проверяет чтение Parquet-файла."""
        import polars as pl
        
        parquet_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "lesson03", "data", "auth_events.parquet"
        )
        
        if not os.path.exists(parquet_path):
            pytest.skip("Parquet-файл не найден")
        
        df = pl.read_parquet(parquet_path)
        assert df.shape[0] > 0, "DataFrame должен содержать данные"

    def test_lazyframe(self):
        """Проверяет работу LazyFrame."""
        import polars as pl
        
        parquet_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "lesson03", "data", "auth_events.parquet"
        )
        
        if not os.path.exists(parquet_path):
            pytest.skip("Parquet-файл не найден")
        
        lf = pl.scan_parquet(parquet_path)
        result = lf.select(pl.count()).collect()
        assert result[0, 0] > 0


class TestMLIntegration:
    """Тесты для ML-компонентов."""

    def test_sklearn_import(self):
        """Проверяет, что sklearn установлен."""
        from sklearn.ensemble import IsolationForest
        assert IsolationForest is not None

    def test_isolation_forest_basic(self):
        """Базовый тест Isolation Forest."""
        from sklearn.ensemble import IsolationForest
        import numpy as np
        
        # Простые данные с одной аномалией
        X = np.array([
            [1, 1], [1, 2], [2, 1], [2, 2],  # Нормальные точки
            [10, 10]  # Аномалия
        ])
        
        model = IsolationForest(contamination=0.2, random_state=42)  # pyright: ignore[reportArgumentType]
        predictions = model.fit_predict(X)
        
        # Последняя точка должна быть аномалией
        assert predictions[-1] == -1, "Аномалия не обнаружена"
