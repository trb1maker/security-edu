# Блок 3. Хранение данных

## Проблема: почему одна база — не всегда решение?

В предыдущих блоках мы настроили сбор логов и их отправку в PostgreSQL. Это работает, пока данных немного. Но что происходит, когда:

- Логов миллионы записей в день?
- Нужно делать сложную аналитику за месяц?
- Запросы начинают выполняться минутами вместо секунд?

Здесь мы сталкиваемся с фундаментальным разделением в мире баз данных: __OLTP vs OLAP__.

## OLTP vs OLAP: два мира данных

__OLTP (Online Transaction Processing)__ — системы для оперативной обработки транзакций:

- Много мелких операций (INSERT, UPDATE)
- Работа с отдельными записями
- Главное — быстро записать и найти конкретную запись
- Примеры: PostgreSQL, MySQL, Oracle

__OLAP (Online Analytical Processing)__ — системы для аналитики:

- Редкие, но тяжёлые запросы (агрегации по миллионам строк)
- Чтение больших объёмов данных
- Главное — быстро просканировать и агрегировать
- Примеры: DuckDB, ClickHouse, BigQuery


### Когда что использовать?

| Задача | OLTP (PostgreSQL) | OLAP (DuckDB) |
|--------|-------------------|---------------|
| Запись новых событий | Идеально | Не для этого |
| Найти конкретное событие по ID | Быстро | Можно, но не оптимально |
| Подсчитать события за час | Терпимо | Идеально |
| Агрегация за месяц по 10 полям | Медленно | Быстро |
| Построить отчёт по 100 млн записей | Очень медленно | Приемлемо |

__В реальных системах используют оба подхода:__

- PostgreSQL принимает и хранит свежие данные
- DuckDB (или другая OLAP-система) используется для аналитики

## PostgreSQL: проектирование схемы для логов

### Принципы проектирования

__1. Денормализация — норма для логов__

В классических OLTP-системах мы стремимся к нормализации. Но для логов это часто плохая идея:

```sql
-- Плохо: нормализованная схема для логов
CREATE TABLE users (id SERIAL PRIMARY KEY, username TEXT);
CREATE TABLE ips (id SERIAL PRIMARY KEY, address INET);
CREATE TABLE events (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    ip_id INT REFERENCES ips(id),
    event_type TEXT,
    timestamp TIMESTAMPTZ
);
```

Проблема: каждый аналитический запрос требует JOIN, что медленно.

```sql
-- Хорошо: денормализованная схема
CREATE TABLE auth_events (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL,
    username TEXT,
    source_ip INET,
    success BOOLEAN,
    details JSONB
);
```

__2. Правильные типы данных__

- `TIMESTAMPTZ` для времени (всегда с timezone!)
- `INET` для IP-адресов (поддерживает операции с подсетями)
- `JSONB` для произвольных полей (индексируемый)
- `TEXT` вместо `VARCHAR` (в PostgreSQL разницы нет)

__3. Не забывайте про NULL__

```sql
-- Поля, которые всегда должны быть заполнены
timestamp TIMESTAMPTZ NOT NULL,
event_type TEXT NOT NULL,

-- Поля, которые могут отсутствовать
username TEXT,  -- NULL для системных событий
```

### Индексы: ускоряем типичные запросы

__B-tree индекс__ — универсальный выбор:

```sql
-- Для поиска по диапазону времени
CREATE INDEX idx_auth_timestamp ON auth_events(timestamp);

-- Для фильтрации по конкретным значениям
CREATE INDEX idx_auth_type ON auth_events(event_type);

-- Составной индекс для частых комбинаций
CREATE INDEX idx_auth_ip_time ON auth_events(source_ip, timestamp);
```

__BRIN индекс__ — для больших таблиц с естественным порядком:

```sql
-- Если данные вставляются последовательно по времени
CREATE INDEX idx_auth_timestamp_brin ON auth_events 
    USING BRIN(timestamp);
```

BRIN занимает в 100-1000 раз меньше места, чем B-tree, но работает только если данные физически упорядочены.

__GIN индекс__ — для JSONB полей:

```sql
-- Поиск по любому полю внутри JSONB
CREATE INDEX idx_auth_details ON auth_events USING GIN(details);
```

### Партиционирование: разделяй и властвуй

Когда таблица растёт до десятков миллионов строк, даже индексы не спасают. Решение — партиционирование:

```sql
-- Создаём партиционированную таблицу
CREATE TABLE auth_events (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL,
    username TEXT,
    source_ip INET,
    success BOOLEAN,
    details JSONB
) PARTITION BY RANGE (timestamp);

-- Создаём партиции по месяцам
CREATE TABLE auth_events_2024_01 
    PARTITION OF auth_events
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

CREATE TABLE auth_events_2024_02 
    PARTITION OF auth_events
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');
```

__Преимущества:__

- Запросы за конкретный период сканируют только нужные партиции
- Старые данные можно удалить, просто удалив партицию
- Обслуживание (VACUUM, REINDEX) делается по частям


### EXPLAIN ANALYZE: понимаем, что происходит

Любой запрос можно профилировать:

```sql
EXPLAIN ANALYZE
SELECT source_ip, COUNT(*) 
FROM auth_events 
WHERE timestamp > NOW() - INTERVAL '1 hour'
  AND success = false
GROUP BY source_ip
ORDER BY COUNT(*) DESC
LIMIT 10;
```

Вывод покажет:

- Какой план выбрал оптимизатор
- Использовались ли индексы
- Сколько времени заняла каждая операция
- Сколько строк реально обработано

__Ключевые сигналы проблем:__

- `Seq Scan` на большой таблице — нужен индекс
- `actual rows` сильно отличается от `estimated` — устаревшая статистика
- `Sort` с `external merge` — не хватает памяти

## DuckDB: швейцарский нож аналитика

DuckDB — это не просто «SQLite для аналитики». Это __универсальный инструмент для работы с данными__, который решает задачи от быстрого исследования файла до построения аналитических пайплайнов.

### Почему DuckDB стал таким популярным?

__1. Нулевая настройка__

- Один файл, никаких серверов
- `pip install duckdb` — и готово
- Работает в Jupyter, скриптах, CLI

__2. Читает всё подряд__

```sql
-- CSV (с автоопределением схемы)
SELECT * FROM 'logs.csv';

-- JSON / NDJSON
SELECT * FROM 'events.json';

-- Parquet (один файл или директория)
SELECT * FROM 'data/*.parquet';

-- Excel (да, даже это)
SELECT * FROM read_xlsx('report.xlsx');

-- PostgreSQL напрямую
SELECT * FROM postgres_scan('connection_string', 'schema', 'table');

-- Даже HTTP!
SELECT * FROM 'https://example.com/data.csv';
```

__В любой непонятной ситуации — открой файл в DuckDB.__ Нужно посмотреть структуру CSV? Быстро агрегировать JSON-логи? Сконвертировать Excel в Parquet? DuckDB справится.

__3. Гибкий SQL-синтаксис__

DuckDB расширяет стандартный SQL синтаксисом, который ускоряет повседневную работу:

```sql
-- FROM можно писать первым (удобно для автодополнения)
FROM auth_events
SELECT source_ip, COUNT(*)
WHERE success = false
GROUP BY source_ip;

-- SELECT * EXCLUDE — все колонки кроме указанных
SELECT * EXCLUDE (details, raw_log) FROM auth_events;

-- SELECT * REPLACE — заменить колонку на выражение
SELECT * REPLACE (upper(username) AS username) FROM auth_events;

-- COLUMNS() — операции над несколькими колонками
SELECT COLUMNS('.*_count') FROM stats;  -- все колонки по паттерну
SELECT MAX(COLUMNS(*)) FROM metrics;     -- MAX от каждой колонки

-- GROUP BY ALL — автоматическая группировка
SELECT source_ip, event_type, COUNT(*)
FROM auth_events
GROUP BY ALL;  -- вместо GROUP BY source_ip, event_type

-- ORDER BY ALL — сортировка по всем SELECT-колонкам
SELECT source_ip, COUNT(*) as cnt
FROM auth_events
GROUP BY ALL
ORDER BY ALL;

-- Группировка и сортировка по алиасам
SELECT source_ip, COUNT(*) as cnt
FROM auth_events
GROUP BY source_ip
ORDER BY cnt DESC;  -- работает! (в PostgreSQL нужно ORDER BY 2)

-- QUALIFY — фильтрация после оконных функций
SELECT *, ROW_NUMBER() OVER (PARTITION BY source_ip ORDER BY timestamp) as rn
FROM auth_events
QUALIFY rn = 1;  -- вместо подзапроса с WHERE
```

__4. Умные значения по умолчанию__

```sql
-- Автоопределение разделителя и заголовков
SELECT * FROM 'data.csv';

-- UNION ALL BY NAME — объединение по именам колонок
SELECT * FROM 'jan.csv'
UNION ALL BY NAME
SELECT * FROM 'feb.csv';  -- даже если порядок колонок разный

-- Friendly SQL: регистронезависимые ключевые слова
from AUTH_EVENTS select count(*)
```

### DuckDB как инструмент подготовки данных

DuckDB отлично подходит не только для аналитики, но и для ETL-задач:

```sql
-- Конвертация форматов
COPY (SELECT * FROM 'raw_logs.json') TO 'logs.parquet' (FORMAT PARQUET);

-- Объединение файлов
COPY (SELECT * FROM 'logs/*.csv') TO 'all_logs.parquet' (FORMAT PARQUET);

-- Очистка и трансформация
COPY (
    SELECT 
        timestamp,
        lower(trim(username)) as username,
        source_ip,
        CASE WHEN status < 400 THEN 'ok' ELSE 'error' END as result
    FROM 'raw_data.csv'
    WHERE timestamp IS NOT NULL
) TO 'clean_data.parquet' (FORMAT PARQUET);
```

__Типичные сценарии:__

- Быстро посмотреть, что внутри файла (`FROM 'file.csv' LIMIT 10`)
- Сконвертировать CSV/JSON в Parquet для дальнейшей работы
- Объединить данные из разных источников
- Очистить и нормализовать данные перед загрузкой в БД

### Колоночное хранение: почему аналитика быстрее?

__Строковое хранение (PostgreSQL):__

```
Row 1: [timestamp, event_type, username, source_ip, success, details]
Row 2: [timestamp, event_type, username, source_ip, success, details]
Row 3: [timestamp, event_type, username, source_ip, success, details]
```

При запросе `SELECT source_ip, COUNT(*) ... GROUP BY source_ip` читаются все колонки всех строк.

__Колоночное хранение (DuckDB):__

```
Column timestamp: [val1, val2, val3, ...]
Column event_type: [val1, val2, val3, ...]
Column source_ip: [val1, val2, val3, ...]
...
```

При том же запросе читается только колонка `source_ip`. Если колонок 10, а нужны 2 — читаем в 5 раз меньше данных.

__Дополнительные преимущества:__

- Одинаковые данные в колонке отлично сжимаются
- Векторные операции над массивами значений
- Эффективное использование CPU кэша

### Parquet: файловый формат для аналитики

__Parquet__ — колоночный формат файлов, стандарт в мире данных:

- Колоночное хранение с компрессией
- Метаданные о схеме и статистика
- Поддерживается везде: Spark, Pandas, Polars, DuckDB

```python
import duckdb

# Экспорт в Parquet
duckdb.sql("""
    COPY (SELECT * FROM read_csv('logs.csv')) 
    TO 'logs.parquet' (FORMAT PARQUET)
""")

# Чтение из Parquet
duckdb.sql("SELECT * FROM 'logs.parquet' WHERE status >= 400")
```

__Сравнение форматов:__

| Формат | Размер (1M записей) | Чтение для агрегации |
|--------|--------------------|--------------------|
| CSV | ~100 MB | Медленно |
| JSON | ~150 MB | Очень медленно |
| Parquet | ~20 MB | Быстро |

### DuckDB + PostgreSQL: лучшее из двух миров

DuckDB умеет читать данные напрямую из PostgreSQL:

```python
import duckdb

duckdb.sql("INSTALL postgres; LOAD postgres;")

# Подключение к PostgreSQL
duckdb.sql("""
    ATTACH 'postgresql://user:pass@localhost/db' AS pg (TYPE postgres)
""")

# Аналитика по данным из PostgreSQL
duckdb.sql("""
    SELECT source_ip, COUNT(*) as cnt
    FROM pg.auth_events
    WHERE timestamp > '2024-01-01'
    GROUP BY source_ip
    ORDER BY cnt DESC
    LIMIT 100
""")
```

__Типичный workflow:__

1. Vector пишет логи в PostgreSQL (OLTP)
2. Периодически экспортируем в Parquet (архив)
3. Аналитика через DuckDB по PostgreSQL и/или Parquet

## Альтернативы и когда их использовать

__ClickHouse__ — мощная OLAP-система:

- Нужен отдельный сервер
- Лучше для очень больших объёмов (терабайты+)
- Сложнее в настройке

__TimescaleDB__ — расширение PostgreSQL для временных рядов:

- Остаётся PostgreSQL (знакомый SQL)
- Автоматическое партиционирование
- Хороший компромисс

__SQLite__ — для совсем маленьких проектов:

- Простота
- Не для аналитики (строковое хранение)

## Полезные ресурсы

- [PostgreSQL: Indexes](https://www.postgresql.org/docs/current/indexes.html)
- [PostgreSQL: Table Partitioning](https://www.postgresql.org/docs/current/ddl-partitioning.html)
- [PostgreSQL: EXPLAIN](https://www.postgresql.org/docs/current/using-explain.html)
- [DuckDB Documentation](https://duckdb.org/docs/)
- [DuckDB: PostgreSQL Extension](https://duckdb.org/docs/extensions/postgres.html)
- [Apache Parquet](https://parquet.apache.org/)

## Практические задания

### Задание 3.1: Схема и индексы в PostgreSQL

Используя данные из генератора `log_generator.py` (Блок 1), выполните следующие задачи:

1. Проанализируйте текущую схему таблицы `auth_events`
2. Создайте индексы для ускорения типичных аналитических запросов
3. Выполните набор аналитических запросов и замерьте время выполнения с помощью `EXPLAIN ANALYZE`

__Запросы для выполнения:__

1. TOP-10 IP-адресов по количеству неудачных попыток входа за последние 24 часа
2. Распределение событий по часам суток
3. Пользователи с успешным входом после серии неудачных попыток (потенциальный brute-force)

__Чеклист выполнения:__

- [ ] Индексы созданы и обоснованы
- [ ] Запросы выполнены с `EXPLAIN ANALYZE`
- [ ] Зафиксировано время выполнения каждого запроса
- [ ] Результаты сохранены для сравнения с DuckDB

### Задание 3.2: Аналитика в DuckDB

Выполните те же аналитические запросы с использованием DuckDB:

1. Подключитесь к PostgreSQL из DuckDB
2. Выполните те же 3 запроса
3. Экспортируйте данные в Parquet
4. Выполните запросы по Parquet-файлу
5. Сравните производительность всех трёх вариантов

__Чеклист выполнения:__

- [ ] DuckDB подключен к PostgreSQL
- [ ] Запросы выполнены через DuckDB → PostgreSQL
- [ ] Данные экспортированы в Parquet
- [ ] Запросы выполнены по Parquet
- [ ] Составлена таблица сравнения производительности
- [ ] Сделаны выводы о применимости каждого подхода
