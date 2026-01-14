# Структура данных

Этот документ описывает структуру данных, используемых в курсе. Данные представлены в формате Parquet и могут быть загружены в PostgreSQL, DuckDB или обработаны с помощью Polars.

## Общая информация

- __Формат данных:__ Parquet
- __Период данных:__ 81 день (1 января - 22 марта 2024)
- __Версии датасета:__
  - `lite`: 14 дней атаки (дни 61-74) (~500 MB)
  - `full`: полный набор данных за 81 день (~2.1 GB)

## Типы данных

### 1. Auth Events (События аутентификации)

__Файл:__ `auth_events.parquet`

__Описание:__ События входа/выхода пользователей в систему.

__Схема:__

| Поле         | Тип       | Описание                                                  |
| ------------ | --------- | --------------------------------------------------------- |
| `timestamp`  | TIMESTAMP | Время события (UTC)                                       |
| `event_type` | VARCHAR   | Тип события: `login_success`, `login_failure`, `logout`   |
| `username`   | VARCHAR   | Имя пользователя                                          |
| `source_ip`  | VARCHAR   | IP-адрес источника (IPv4)                                 |
| `success`    | BOOLEAN   | Успешность операции                                       |
| `details`    | JSON      | Дополнительные детали (method, user_agent, reason и т.д.) |

__Пример записи:__

```json
{
  "timestamp": "2024-03-08T03:47:22.456Z",
  "event_type": "login_success",
  "username": "dev_sergey",
  "source_ip": "203.0.113.42",
  "success": true,
  "details": {
    "method": "password",
    "user_agent": "python-requests/2.28.0",
    "suspicious": true
  }
}
```

__Формат в JSON (для Vector):__

```json
{"timestamp": "2024-03-08T03:47:22.456Z", "event_type": "login_success", "username": "dev_sergey", "source_ip": "203.0.113.42", "success": true, "details": {"method": "password", "user_agent": "python-requests/2.28.0"}}
```

__Объем данных:__
- Нормальный день: ~50,000 событий
- День атаки: ~80,000 событий

---

### 2. Nginx Logs (Веб-логи)

__Файл:__ `nginx_logs.parquet`

__Описание:__ Логи веб-сервера nginx в формате Combined Log Format.

__Схема:__

| Поле         | Тип       | Описание                               |
| ------------ | --------- | -------------------------------------- |
| `timestamp`  | TIMESTAMP | Время запроса (UTC)                    |
| `source_ip`  | VARCHAR   | IP-адрес клиента (IPv4)                |
| `method`     | VARCHAR   | HTTP-метод (GET, POST, PUT и т.д.)     |
| `path`       | VARCHAR   | Путь запроса                           |
| `status`     | INTEGER   | HTTP-код ответа (200, 404, 403 и т.д.) |
| `size`       | INTEGER   | Размер ответа в байтах                 |
| `referer`    | VARCHAR   | Referer заголовок (или "-")            |
| `user_agent` | VARCHAR   | User-Agent заголовок                   |

__Пример записи:__

```json
{
  "timestamp": "2024-03-01T10:15:32.000Z",
  "source_ip": "203.0.113.42",
  "method": "GET",
  "path": "/admin",
  "status": 403,
  "size": 162,
  "referer": "-",
  "user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
}
```

__Формат в Combined Log Format (для Vector):__

```
203.0.113.42 - - [01/Mar/2024:10:15:32 +0000] "GET /admin HTTP/1.1" 403 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
```

__Объем данных:__
- Нормальный день: ~500,000 запросов
- День атаки: ~800,000 запросов

---

### 3. DNS Queries (DNS-запросы)

__Файл:__ `dns_queries.parquet`

__Описание:__ DNS-запросы в формате BIND query log.

__Схема:__

| Поле            | Тип       | Описание                                  |
| --------------- | --------- | ----------------------------------------- |
| `timestamp`     | TIMESTAMP | Время запроса (UTC)                       |
| `source_ip`     | VARCHAR   | IP-адрес клиента (IPv4)                   |
| `source_port`   | INTEGER   | Порт клиента                              |
| `query_domain`  | VARCHAR   | Запрашиваемый домен                       |
| `query_type`    | VARCHAR   | Тип записи (A, AAAA, TXT, MX и т.д.)      |
| `response_code` | VARCHAR   | Код ответа DNS (NOERROR, NXDOMAIN и т.д.) |
| `resolved_ip`   | VARCHAR   | Резолвленный IP-адрес (если есть)         |
| `resolver`      | VARCHAR   | IP-адрес DNS-резолвера                    |

__Пример записи:__

```json
{
  "timestamp": "2024-03-12T14:23:45.123Z",
  "source_ip": "192.168.1.100",
  "source_port": 54321,
  "query_domain": "x7kj2m9p.data-sync.xyz",
  "query_type": "A",
  "response_code": "NOERROR",
  "resolved_ip": "45.33.32.156",
  "resolver": "8.8.8.8"
}
```

__Формат в BIND query log (для Vector):__

```
12-Mar-2024 14:23:45.123 client @0x7f9b2c001a00 192.168.1.100#54321 (x7kj2m9p.data-sync.xyz): query: x7kj2m9p.data-sync.xyz IN A +E(0)K (8.8.8.8)
```

__Объем данных:__
- Нормальный день: ~200,000 запросов
- День атаки: ~300,000 запросов

---

### 4. Firewall Events (События фаервола)

__Файл:__ `firewall_events.parquet`

__Описание:__ События фаервола в формате CEF (Common Event Format).

__Схема:__

| Поле             | Тип       | Описание                                                         |
| ---------------- | --------- | ---------------------------------------------------------------- |
| `timestamp`      | TIMESTAMP | Время события (UTC)                                              |
| `source_ip`      | VARCHAR   | IP-адрес источника (IPv4)                                        |
| `dest_ip`        | VARCHAR   | IP-адрес назначения (IPv4)                                       |
| `source_port`    | INTEGER   | Порт источника                                                   |
| `dest_port`      | INTEGER   | Порт назначения                                                  |
| `protocol`       | VARCHAR   | Протокол (TCP, UDP, ICMP)                                        |
| `action`         | VARCHAR   | Действие фаервола (ALLOW, BLOCK)                                 |
| `bytes_sent`     | INTEGER   | Отправлено байт                                                  |
| `bytes_received` | INTEGER   | Получено байт                                                    |
| `reason`         | VARCHAR   | Причина действия (policy, port_scan, brute_force_attempt и т.д.) |

__Пример записи:__

```json
{
  "timestamp": "2024-03-01T10:15:32.000Z",
  "source_ip": "203.0.113.42",
  "dest_ip": "192.168.1.10",
  "source_port": 45678,
  "dest_port": 22,
  "protocol": "TCP",
  "action": "BLOCK",
  "bytes_sent": 60,
  "bytes_received": 0,
  "reason": "port_scan"
}
```

__Формат в CEF (для Vector):__

```
Mar 01 10:15:32 fw-gateway CEF:0|FinanceFlow|Firewall|1.0|200|Connection block|7|src=203.0.113.42 dst=192.168.1.10 spt=45678 dpt=22 proto=TCP act=block reason=port_scan
```

__Объем данных:__
- Нормальный день: ~100,000 событий
- День атаки: ~150,000 событий

---

## Структура файлов в Parquet

### Организация по дням

Данные разделены на партиции по дням для эффективной загрузки:

```
data/
├── lite/
│   ├── manifest.json
│   ├── auth_events/
│   │   ├── day=61/
│   │   ├── day=62/
│   │   └── ...
│   ├── nginx_logs/
│   │   ├── day=61/
│   │   └── ...
│   ├── dns_queries/
│   │   └── ...
│   └── firewall_events/
│       └── ...
└── full/
    └── (аналогичная структура для всех 81 дней)
```

### Manifest.json

Каждая версия датасета содержит файл `manifest.json` с метаданными:

```json
{
  "version": "lite",
  "generated_at": "2024-01-15T10:00:00Z",
  "schema_version": "1.0",
  "files": [
    {
      "name": "auth_events/day=61/part-0.parquet",
      "size": 1234567,
      "sha256": "abc123...",
      "row_count": 50000
    },
    ...
  ],
  "total_size": 524288000,
  "total_rows": 14000000
}
```

---

## Работа с данными

### Загрузка в DuckDB

```python
import duckdb

conn = duckdb.connect()
conn.execute("""
    SELECT * 
    FROM read_parquet('data/lite/auth_events/day=61/*.parquet')
    LIMIT 10
""")
```

### Загрузка в Polars

```python
import polars as pl

df = pl.read_parquet("data/lite/auth_events/day=61/*.parquet")
```

### Загрузка в PostgreSQL

Данные могут быть загружены через Vector или напрямую через Python скрипты.

---

## Индексы и оптимизация

Для эффективных запросов рекомендуется создать индексы:

__Auth Events:__
- `timestamp`
- `source_ip`
- `username`
- `event_type`
- `success`

__Nginx Logs:__
- `timestamp`
- `source_ip`
- `status`
- `path`

__DNS Queries:__
- `timestamp`
- `source_ip`
- `query_domain`

__Firewall Events:__
- `timestamp`
- `source_ip`
- `dest_ip`
- `dest_port`
- `action`

---

## Примечания

1. Все временные метки в формате UTC
2. IP-адреса в формате IPv4 (строка)
3. JSON-поля могут содержать дополнительные поля в зависимости от типа события
4. Данные детерминированы (используются фиксированные seed-значения)
5. Партиционирование по дням позволяет эффективно загружать только нужные периоды
