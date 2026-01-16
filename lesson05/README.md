# Блок 5. Python для обработки данных

## Предыстория

__День 15. Кабинет начальника SOC__

Дмитрий просматривает ваш отчет по SQL-анализу инцидента FIN-2024-001. Он кивает с удовлетворением, но затем поворачивается к вам:

_"Алексей, отличная работа! Ты нашел все ключевые этапы атаки. Но CISO Елена Васильевна попросила углубить анализ. У нее три вопроса:_

_1. __Автоматизация DGA-детекции.__ Ты нашел домены `*.data-sync.xyz` вручную, перебирая результаты SQL-запросов. А если бы таких доменов было 10,000? Нам нужен алгоритм, который автоматически выявляет DGA-домены по их характеристикам._

_2. __Поиск других скомпрометированных учетных записей.__ Ты подтвердил компрометацию `dev_sergey`. Но могли ли атакующие взломать еще кого-то? Нужна ML-модель для поиска аномальных паттернов поведения всех пользователей._

_3. __Подготовка данных для дашборда.__ Завтра встреча с руководством, нужно показать визуализацию. Подготовь агрегированные данные для Grafana."_

Дмитрий передает вам ноутбук:

_"SQL здесь не поможет - нужны сложные математические вычисления и машинное обучение. Пора использовать Python и Polars. У тебя есть до конца дня."_

---

## Зачем Python, если есть SQL?

SQL отлично справляется с агрегациями и фильтрацией. Но некоторые задачи требуют большей гибкости:

- __Расчёт энтропии__ для выявления DGA-доменов
- __Работа с IP-подсетями__ и геолокация
- __Машинное обучение__ для обнаружения аномалий
- __Сложные трансформации__ данных из разных форматов
- __Визуализация__ результатов анализа

В этом блоке мы используем __Polars__ — современную библиотеку для работы с данными, которая быстрее pandas и имеет более удобный API.

## Занятие 5.1: Polars для обработки данных

### Почему Polars, а не Pandas?

| Критерий | Pandas | Polars |
|----------|--------|--------|
| Скорость | Базовая | В 5-50 раз быстрее |
| Память | Высокое потребление | Эффективное использование |
| Многопоточность | Нет | Да, из коробки |
| Ленивые вычисления | Нет | Да (LazyFrame) |
| API | Местами запутанный | Консистентный |

__Polars__ использует Apache Arrow под капотом и написан на Rust, что даёт ему преимущество в производительности.

### Основные концепции

__DataFrame__ — таблица в памяти:

```python
import polars as pl

# Создание DataFrame
df = pl.DataFrame({
    "ip": ["192.168.1.1", "10.0.0.5", "192.168.1.1"],
    "event": ["login", "logout", "login"],
    "success": [True, True, False]
})

# Чтение из файла
df = pl.read_parquet("auth_events.parquet")
df = pl.read_csv("logs.csv")
```

__LazyFrame__ — отложенные вычисления:

```python
# LazyFrame не выполняет операции сразу
lf = pl.scan_parquet("auth_events.parquet")

# Строим цепочку операций
result = (
    lf
    .filter(pl.col("success") == False)
    .group_by("source_ip")
    .agg(pl.count().alias("failed_count"))
    .sort("failed_count", descending=True)
    .limit(10)
    .collect()  # Только здесь выполняется запрос
)
```

__Выражения (Expressions)__ — декларативный способ описания трансформаций:

```python
# Выражения можно комбинировать
df.select(
    pl.col("username"),
    pl.col("source_ip"),
    pl.col("timestamp").dt.hour().alias("hour"),
    pl.when(pl.col("success")).then(1).otherwise(0).alias("success_int")
)
```

### Типичные операции

__Фильтрация:__

```python
# Простой фильтр
df.filter(pl.col("success") == False)

# Множественные условия
df.filter(
    (pl.col("success") == False) & 
    (pl.col("event_type") == "ssh_login")
)
```

__Агрегации:__

```python
df.group_by("source_ip").agg(
    pl.count().alias("total"),
    pl.col("success").sum().alias("successful"),
    (pl.col("success") == False).sum().alias("failed")
)
```

__Работа с временем:__

```python
df.with_columns(
    pl.col("timestamp").dt.hour().alias("hour"),
    pl.col("timestamp").dt.weekday().alias("weekday"),
    pl.col("timestamp").dt.date().alias("date")
)
```

__Оконные функции:__

```python
df.with_columns(
    pl.col("timestamp")
    .diff()
    .over("username")
    .alias("time_since_prev")
)
```

## Занятие 5.2: Python для задач, выходящих за рамки SQL

### Расчёт энтропии для DGA-детекции

__Энтропия Шеннона__ измеряет "случайность" строки. DGA-домены имеют высокую энтропию.

```python
import math
from collections import Counter

def shannon_entropy(s: str) -> float:
    """Вычисляет энтропию Шеннона для строки."""
    if not s:
        return 0.0
    
    # Считаем частоты символов
    freq = Counter(s)
    length = len(s)
    
    # Вычисляем энтропию
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
    return entropy

# Примеры
print(shannon_entropy("google"))      # ~2.25 (низкая - повторяющиеся буквы)
print(shannon_entropy("x7kj2m9p"))    # ~3.0  (высокая - случайные символы)
print(shannon_entropy("aaaaaa"))      # 0.0   (минимальная - один символ)
```

__Применение к доменам:__

```python
import polars as pl

def detect_dga(df: pl.DataFrame) -> pl.DataFrame:
    """Добавляет метрики для DGA-детекции."""
    return df.with_columns(
        # Извлекаем поддомен (до первой точки)
        pl.col("domain")
        .str.split(".")
        .list.first()
        .alias("subdomain"),
    ).with_columns(
        # Длина поддомена
        pl.col("subdomain").str.len_chars().alias("subdomain_length"),
        
        # Количество цифр
        pl.col("subdomain")
        .str.count_matches(r"\d")
        .alias("digit_count"),
        
        # Энтропия (через map_elements)
        pl.col("subdomain")
        .map_elements(shannon_entropy, return_dtype=pl.Float64)
        .alias("entropy")
    ).with_columns(
        # Классификация
        pl.when(
            (pl.col("entropy") > 3.0) | 
            (pl.col("subdomain_length") > 15) |
            (pl.col("digit_count") > 3)
        )
        .then(pl.lit("suspicious"))
        .otherwise(pl.lit("normal"))
        .alias("classification")
    )
```

### Работа с IP-адресами

Модуль `ipaddress` позволяет работать с IP-адресами и подсетями:

```python
import ipaddress

# Парсинг IP
ip = ipaddress.ip_address("192.168.1.1")
print(ip.is_private)      # True
print(ip.is_global)       # False
print(ip.is_loopback)     # False

# Работа с подсетями
network = ipaddress.ip_network("192.168.0.0/16")
print(ip in network)      # True

# Проверка RFC1918 (приватные сети)
private_networks = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def is_internal(ip_str: str) -> bool:
    """Проверяет, является ли IP внутренним."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in private_networks)
    except ValueError:
        return False
```

__Применение в Polars:__

```python
df.with_columns(
    pl.col("source_ip")
    .map_elements(is_internal, return_dtype=pl.Boolean)
    .alias("is_internal")
)
```

### Интеграция с DuckDB

Polars отлично работает с DuckDB:

```python
import duckdb
import polars as pl

# Polars DataFrame → DuckDB
df = pl.DataFrame({"a": [1, 2, 3], "b": ["x", "y", "z"]})
result = duckdb.sql("SELECT * FROM df WHERE a > 1").pl()

# DuckDB → Polars
result = duckdb.sql("SELECT * FROM 'data.parquet'").pl()
```

## Занятие 5.3: Машинное обучение для обнаружения аномалий

### Почему ML для ИБ?

Правила (SQL-запросы) хорошо ловят известные паттерны. Но как найти неизвестные атаки?

__Anomaly Detection__ — поиск точек данных, которые "не похожи" на остальные:

- Нетипичное поведение пользователя
- Необычные паттерны трафика
- Выбросы в метриках

### Isolation Forest

__Isolation Forest__ — алгоритм, который изолирует аномалии:

- Строит случайные деревья решений
- Аномалии изолируются быстрее (меньше разбиений)
- Не требует размеченных данных

```python
from sklearn.ensemble import IsolationForest
import polars as pl
import numpy as np

# Подготовка признаков
def prepare_features(df: pl.DataFrame) -> np.ndarray:
    """Создаёт признаки для ML."""
    features = df.select(
        pl.col("events_per_hour"),
        pl.col("failed_ratio"),
        pl.col("unique_ips"),
        pl.col("avg_time_between_events")
    ).to_numpy()
    return features

# Обучение модели
model = IsolationForest(
    n_estimators=100,      # Количество деревьев
    contamination=0.05,    # Ожидаемая доля аномалий (5%)
    random_state=42
)

X = prepare_features(df)
predictions = model.fit_predict(X)

# -1 = аномалия, 1 = норма
df = df.with_columns(
    pl.Series("is_anomaly", predictions == -1)
)
```

### Feature Engineering для ИБ

Качество ML-модели зависит от признаков. Типичные признаки для ИБ-данных:

__Для пользователя:__

- Количество событий за период
- Соотношение успешных/неудачных входов
- Количество уникальных IP
- Среднее время между событиями
- Активность в нерабочее время (%)

__Для IP-адреса:__

- Количество целевых пользователей
- Количество уникальных портов
- Объём трафика
- Соотношение входящего/исходящего

```python
def extract_user_features(df: pl.DataFrame) -> pl.DataFrame:
    """Извлекает признаки для каждого пользователя."""
    return df.group_by("username").agg(
        # Количество событий
        pl.count().alias("total_events"),
        
        # Успешность
        pl.col("success").mean().alias("success_rate"),
        
        # Уникальные IP
        pl.col("source_ip").n_unique().alias("unique_ips"),
        
        # Временные характеристики
        pl.col("timestamp").diff().mean().alias("avg_interval"),
        pl.col("timestamp").diff().std().alias("std_interval"),
        
        # Активность в нерабочее время
        (
            (pl.col("timestamp").dt.hour() < 9) | 
            (pl.col("timestamp").dt.hour() > 18)
        ).mean().alias("non_working_ratio")
    )
```

### Интерпретация результатов

ML-модель нашла аномалии. Что дальше?

```python
# Получаем топ-аномалий
anomalies = df.filter(pl.col("is_anomaly"))

# Смотрим, что их отличает от нормы
print("Средние значения признаков:")
print("Норма:", df.filter(~pl.col("is_anomaly")).select(features).mean())
print("Аномалии:", anomalies.select(features).mean())

# Исследуем конкретные случаи
for row in anomalies.head(10).iter_rows(named=True):
    print(f"User: {row['username']}")
    print(f"  Events: {row['total_events']}")
    print(f"  Success rate: {row['success_rate']:.2%}")
    print(f"  Unique IPs: {row['unique_ips']}")
```

## Полезные ресурсы

- [Polars User Guide](https://docs.pola.rs/)
- [Polars API Reference](https://docs.pola.rs/api/python/stable/reference/)
- [Python ipaddress](https://docs.python.org/3/library/ipaddress.html)
- [scikit-learn Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)

## Связь с инцидентом FIN-2024-001

В предыдущем блоке вы вручную нашли следующие IoC:

- __IP атакующего:__ `203.0.113.42`
- __Скомпрометированный пользователь:__ `dev_sergey`
- __C2-домены:__ `*.data-sync.xyz` (DGA-поддомены)

В этом блоке вы автоматизируете детекцию:

1. __DGA-детекция:__ Напишете алгоритм, который по энтропии и другим признакам найдет `*.data-sync.xyz` без явного указания домена
2. __Anomaly Detection:__ Построите ML-модель, которая автоматически пометит `dev_sergey` как аномального пользователя
3. __ETL-pipeline:__ Подготовите агрегированные данные для визуализации в Grafana

Это позволит обнаруживать подобные атаки в будущем автоматически, без ручного анализа.

---

## Практические задания

### Задание 5.1: ETL-pipeline на Polars

Создайте pipeline для обработки логов:

1. Загрузите данные из Parquet-файла с помощью `scan_parquet` (LazyFrame)
2. Добавьте колонки: час события, день недели, флаг "нерабочее время"
3. Отфильтруйте только неудачные попытки входа
4. Сгруппируйте по IP и посчитайте статистику
5. Сохраните результат в новый Parquet-файл

__Чеклист выполнения:__

- [ ] Используется LazyFrame (scan_parquet)
- [ ] Добавлены временные колонки
- [ ] Выполнена фильтрация и агрегация
- [ ] Результат сохранён в Parquet

### Задание 5.2: DGA-детекция с энтропией

Реализуйте детектор DGA-доменов:

1. Напишите функцию расчёта энтропии Шеннона
2. Создайте тестовый DataFrame с доменами (нормальными и DGA)
3. Примените функцию энтропии к доменам
4. Классифицируйте домены как "normal" или "suspicious"

__Чеклист выполнения:__

- [ ] Функция энтропии корректно работает
- [ ] Энтропия применена к DataFrame через map_elements
- [ ] Домены классифицированы по порогу энтропии
- [ ] DGA-домены выявлены корректно

### Задание 5.3: Anomaly Detection с Isolation Forest

Постройте модель обнаружения аномалий:

1. Извлеките признаки для каждого пользователя (функция extract_user_features)
2. Обучите Isolation Forest на признаках
3. Найдите аномальных пользователей
4. Проанализируйте, чем аномалии отличаются от нормы

__Чеклист выполнения:__

- [ ] Признаки извлечены корректно
- [ ] Модель обучена
- [ ] Аномалии найдены
- [ ] Проведён анализ отличий аномалий от нормы

---

## Что дальше?

Вы успешно автоматизировали детекцию DGA-доменов и аномальных пользователей с помощью Python. Теперь у вас есть:

- Функция расчета энтропии для любых доменов
- ML-модель для поиска аномальных паттернов поведения
- Агрегированные данные для визуализации

__В следующем блоке__ вы создадите интерактивный дашборд в Grafana, который будет визуализировать все найденные индикаторы компрометации и позволит руководству увидеть полную картину инцидента.
