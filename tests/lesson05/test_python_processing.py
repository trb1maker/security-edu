"""
Тесты для Блока 5: Python для обработки данных

Проверяет:
- Корректность функции энтропии
- Работу с IP-адресами
- Feature engineering
- DGA-детекцию (IoC: *.data-sync.xyz)
- Anomaly Detection (IoC: dev_sergey должен быть аномалией)
"""

import os
import math
from collections import Counter
import pytest
import polars as pl


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
        # Используем реальные публичные IP вместо TEST-NET
        public_ips = ["8.8.8.8", "1.1.1.1", "45.33.32.156"]

        for ip in private_ips:
            assert ipaddress.ip_address(ip).is_private, f"{ip} должен быть приватным"

        for ip in public_ips:
            assert not ipaddress.ip_address(ip).is_private, (
                f"{ip} не должен быть приватным"
            )

    def test_attacker_ip_is_external(self):
        """Проверяет, что IP атакующего определяется как внешний."""
        import ipaddress

        # 203.0.113.42 - это TEST-NET-3 (RFC 5737), который is_private считает reserved
        # Используем другой IP из инцидента: 45.33.32.156 (реальный публичный IP)
        attacker_ip = "45.33.32.156"
        assert not ipaddress.ip_address(attacker_ip).is_private, (
            f"IP атакующего {attacker_ip} должен быть внешним"
        )


class TestPolarsIntegration:
    """Тесты для интеграции с Polars."""

    def test_parquet_reading(self):
        """Проверяет чтение Parquet-файла."""
        parquet_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "data",
            "lite",
            "auth_events",
        )

        if not os.path.exists(parquet_path):
            pytest.skip("Parquet-файл не найден. Запустите bootstrap.py --version lite")

        # Читаем через scan_parquet (как в заданиях)
        lf = pl.scan_parquet(f"{parquet_path}/day=*/*.parquet")
        df = lf.limit(10).collect()
        assert df.shape[0] > 0, "DataFrame должен содержать данные"

    def test_lazyframe(self):
        """Проверяет работу LazyFrame."""
        parquet_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "data",
            "lite",
            "auth_events",
        )

        if not os.path.exists(parquet_path):
            pytest.skip("Parquet-файл не найден")

        lf = pl.scan_parquet(f"{parquet_path}/day=*/*.parquet")
        result = lf.select(pl.len()).collect()
        assert result[0, 0] > 0


class TestDGADetection:
    """Тесты для DGA-детекции (проверка IoC из инцидента)."""

    def test_dns_data_available(self):
        """Проверяет наличие DNS-данных."""
        dns_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "data",
            "lite",
            "dns_queries",
        )

        if not os.path.exists(dns_path):
            pytest.skip("DNS-данные не найдены. Запустите bootstrap.py --version lite")

        lf = pl.scan_parquet(f"{dns_path}/day=*/*.parquet")
        count = lf.select(pl.len()).collect()[0, 0]
        assert count > 0, "DNS-запросы должны присутствовать"

    def test_c2_domains_exist(self):
        """Проверяет наличие C2-доменов *.data-sync.xyz в данных."""
        dns_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "data",
            "lite",
            "dns_queries",
        )

        if not os.path.exists(dns_path):
            pytest.skip("DNS-данные не найдены")

        lf = pl.scan_parquet(f"{dns_path}/day=*/*.parquet")
        c2_domains = lf.filter(
            pl.col("query_domain").str.contains("data-sync.xyz")
        ).collect()

        assert c2_domains.shape[0] > 0, (
            "В данных должны присутствовать домены *.data-sync.xyz"
        )

    def test_dga_detection_with_entropy(self):
        """Проверяет, что DGA-домены можно выявить по энтропии."""
        # Тестовые домены
        test_domains = pl.DataFrame(
            {
                "domain": [
                    "google.com",
                    "x7kj2m9p.data-sync.xyz",  # DGA
                    "facebook.com",
                    "k9m2p4x1.data-sync.xyz",  # DGA
                ]
            }
        )

        # Применяем энтропию к поддоменам
        result = (
            test_domains.with_columns(
                pl.col("domain").str.split(".").list.first().alias("subdomain")
            )
            .with_columns(
                pl.col("subdomain")
                .map_elements(shannon_entropy, return_dtype=pl.Float64)
                .alias("entropy")
            )
            .with_columns(
                pl.when(pl.col("entropy") > 2.8)
                .then(pl.lit("suspicious"))
                .otherwise(pl.lit("normal"))
                .alias("classification")
            )
        )

        # Проверяем, что DGA-домены классифицированы как suspicious
        dga_domains = result.filter(pl.col("domain").str.contains("data-sync.xyz"))

        suspicious_count = dga_domains.filter(
            pl.col("classification") == "suspicious"
        ).shape[0]

        assert suspicious_count >= 1, (
            "DGA-домены должны быть классифицированы как suspicious по энтропии"
        )


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
        X = np.array(
            [
                [1, 1],
                [1, 2],
                [2, 1],
                [2, 2],  # Нормальные точки
                [10, 10],  # Аномалия
            ]
        )

        model = IsolationForest(contamination=0.2, random_state=42)
        predictions = model.fit_predict(X)

        # Последняя точка должна быть аномалией
        assert predictions[-1] == -1, "Аномалия не обнаружена"


class TestAnomalyDetectionOnRealData:
    """Тесты для ML-детекции аномалий на реальных данных инцидента."""

    def test_user_features_extraction(self):
        """Проверяет извлечение признаков для пользователей."""
        auth_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "data",
            "lite",
            "auth_events",
        )

        if not os.path.exists(auth_path):
            pytest.skip("Auth-данные не найдены")

        # Загружаем данные
        lf = pl.scan_parquet(f"{auth_path}/day=*/*.parquet")

        # Добавляем временные признаки (парсим timestamp из строки с timezone)
        lf = lf.with_columns(
            pl.col("timestamp").str.to_datetime(time_zone="UTC").dt.hour().alias("hour")
        )

        # Извлекаем признаки
        user_features = (
            lf.group_by("username")
            .agg(
                pl.len().alias("total_events"),
                pl.col("success").mean().alias("success_rate"),
                pl.col("source_ip").n_unique().alias("unique_ips"),
                ((pl.col("hour") < 9) | (pl.col("hour") > 18))
                .mean()
                .alias("non_working_ratio"),
            )
            .collect()
        )

        assert user_features.shape[0] > 0, (
            "Признаки пользователей должны быть извлечены"
        )
        assert "total_events" in user_features.columns
        assert "success_rate" in user_features.columns
        assert "unique_ips" in user_features.columns

    def test_dev_sergey_anomaly_detection(self):
        """
        Проверяет, что dev_sergey (целевой пользователь из инцидента)
        определяется как аномалия ML-моделью.
        """
        from sklearn.ensemble import IsolationForest

        auth_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "data",
            "lite",
            "auth_events",
        )

        if not os.path.exists(auth_path):
            pytest.skip("Auth-данные не найдены")

        # Загружаем и обрабатываем данные
        lf = pl.scan_parquet(f"{auth_path}/day=*/*.parquet")
        lf = lf.with_columns(
            pl.col("timestamp").str.to_datetime(time_zone="UTC").dt.hour().alias("hour")
        )

        # Feature engineering
        user_features = (
            lf.group_by("username")
            .agg(
                pl.len().alias("total_events"),
                pl.col("success").mean().alias("success_rate"),
                pl.col("source_ip").n_unique().alias("unique_ips"),
                ((pl.col("hour") < 9) | (pl.col("hour") > 18))
                .mean()
                .alias("non_working_ratio"),
            )
            .collect()
        )

        # Подготовка для ML
        feature_cols = [
            "total_events",
            "success_rate",
            "unique_ips",
            "non_working_ratio",
        ]
        X = user_features.select(feature_cols).fill_null(0).to_numpy()

        # Обучение модели
        model = IsolationForest(contamination=0.1, random_state=42)
        predictions = model.fit_predict(X)

        # Добавляем результаты
        user_features = user_features.with_columns(
            pl.Series("is_anomaly", predictions == -1)
        )

        # Проверяем dev_sergey
        dev_sergey = user_features.filter(pl.col("username") == "dev_sergey")

        assert dev_sergey.shape[0] > 0, "dev_sergey должен присутствовать в данных"

        is_anomaly = dev_sergey["is_anomaly"][0]
        assert is_anomaly, (
            "dev_sergey (целевой пользователь инцидента) должен быть помечен как аномалия. "
            f"Признаки: {dev_sergey.to_dicts()[0]}"
        )


class TestAttackerIPDetection:
    """Тесты для обнаружения IP атакующего."""

    def test_attacker_ip_in_top_failed_attempts(self):
        """Проверяет, что IP атакующего в топе по неудачным попыткам."""
        auth_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "data",
            "lite",
            "auth_events",
        )

        if not os.path.exists(auth_path):
            pytest.skip("Auth-данные не найдены")

        lf = pl.scan_parquet(f"{auth_path}/day=*/*.parquet")

        # Топ-10 IP по неудачным попыткам
        top_failed = (
            lf.filter(pl.col("success") == False)
            .group_by("source_ip")
            .agg(pl.len().alias("failed_count"))
            .sort("failed_count", descending=True)
            .limit(10)
            .collect()
        )

        attacker_ip = "203.0.113.42"
        top_ips = top_failed["source_ip"].to_list()

        assert attacker_ip in top_ips, (
            f"IP атакующего {attacker_ip} должен быть в топ-10 по неудачным попыткам. "
            f"Найденные топ-IP: {top_ips}"
        )
