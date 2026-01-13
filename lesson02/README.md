# Блок 2. Сбор и маршрутизация логов

## Проблема: логи везде, порядка нигде

Представьте типичную инфраструктуру компании: веб-серверы пишут логи в `/var/log/nginx/`, приложения — в свои файлы, системные события уходят в syslog, контейнеры выводят в stdout. Каждый источник использует свой формат. Когда случается инцидент, аналитику приходится подключаться к десяткам серверов, искать нужные файлы, разбираться с форматами.

Сборщик логов решает эту проблему: он собирает данные из разных источников, приводит к единому формату и отправляет в централизованное хранилище. Вместо "подключись к серверу и grep'ни логи" вы получаете "открой дашборд и найди всё в одном месте".

## Vector: современный сборщик логов

Vector — это инструмент для сбора, трансформации и отправки логов и метрик. Написан на Rust, что даёт высокую производительность при минимальном потреблении ресурсов.

Почему именно Vector:

- __Производительность.__ Обрабатывает до 10 ТБ данных в день на одном сервере. Для сравнения: Logstash на тех же задачах потребляет в 10 раз больше памяти.
- __Единый конфиг.__ Один TOML/YAML файл описывает весь pipeline. Не нужно изучать несколько инструментов.
- __Богатый язык трансформаций.__ VRL (Vector Remap Language) позволяет парсить, фильтровать и обогащать данные без внешних скриптов.
- __Надёжность.__ Буферизация на диске, at-least-once доставка, автоматическое переподключение.

## Архитектура: Sources → Transforms → Sinks

Vector работает по принципу конвейера. Данные проходят три этапа:

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Sources   │ ──▶ │  Transforms  │ ──▶ │    Sinks    │
│  (откуда)   │     │ (обработка)  │     │   (куда)    │
└─────────────┘     └──────────────┘     └─────────────┘
     │                    │                    │
     ▼                    ▼                    ▼
  - file              - remap              - console
  - syslog            - filter             - file
  - docker_logs       - route              - postgresql
  - stdin             - sample             - elasticsearch
```

__Sources__ читают данные: из файлов, сети, Docker-контейнеров, stdin.

__Transforms__ обрабатывают: парсят JSON, извлекают поля regex'ом, фильтруют, обогащают.

__Sinks__ отправляют: в файлы, базы данных, очереди сообщений, облачные сервисы.

Каждый компонент имеет уникальное имя и может быть связан с другими через поле `inputs`.

## Конфигурация Vector

Vector настраивается через TOML или YAML файл. Вот минимальный пример — читаем stdin, выводим в консоль:

```toml
[sources.my_source]
type = "stdin"

[sinks.my_sink]
type = "console"
inputs = ["my_source"]
encoding.codec = "json"
```

Запуск:

```bash
echo '{"user": "admin", "action": "login"}' | vector --config config.toml
```

Обратите внимание на `inputs = ["my_source"]` — это связывает sink с source. Без этой связи данные никуда не пойдут.

## Sources: откуда читаем данные

### Чтение файлов

Самый распространённый источник — файлы логов:

```toml
[sources.nginx_logs]
type = "file"
include = ["/var/log/nginx/*.log"]
read_from = "beginning"  # или "end" для новых записей
```

Vector отслеживает позицию в файле и не теряет данные при перезапуске.

### Docker-контейнеры

Собираем логи из всех контейнеров:

```toml
[sources.docker]
type = "docker_logs"
```

Vector автоматически добавляет метаданные: имя контейнера, образ, labels.

### Syslog

Принимаем syslog по сети:

```toml
[sources.syslog]
type = "syslog"
address = "0.0.0.0:514"
mode = "udp"
```

## Transforms: обработка данных

Здесь происходит магия. Transform `remap` использует язык VRL для любых манипуляций с данными.

### Парсинг JSON

Если лог уже в JSON-формате:

```toml
[transforms.parse_json]
type = "remap"
inputs = ["my_source"]
source = '''
. = parse_json!(.message)
'''
```

Точка `.` означает текущее событие. `.message` — поле с исходным текстом. `parse_json!` парсит строку в объект. Восклицательный знак означает "падай при ошибке" (есть вариант без — возвращает null).

### Парсинг с regex

Для неструктурированных логов используем regex:

```toml
[transforms.parse_nginx]
type = "remap"
inputs = ["nginx_logs"]
source = '''
. |= parse_regex!(.message, r'^(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\d+)')
'''
```

Оператор `|=` добавляет извлечённые поля к событию.

### Фильтрация

Пропускаем только нужные события:

```toml
[transforms.only_errors]
type = "filter"
inputs = ["parse_nginx"]
condition = '.status >= 400'
```

### Добавление полей

Обогащаем событие дополнительной информацией:

```toml
[transforms.enrich]
type = "remap"
inputs = ["parse_nginx"]
source = '''
.environment = "production"
.processed_at = now()
.source_file = .file
'''
```

### Маршрутизация

Направляем события в разные sinks по условию:

```toml
[transforms.route_by_status]
type = "route"
inputs = ["parse_nginx"]

[transforms.route_by_status.route]
errors = '.status >= 400'
success = '.status < 400'
```

Теперь можно подключить разные sinks к `route_by_status.errors` и `route_by_status.success`.

## Sinks: куда отправляем

### Консоль (для отладки)

```toml
[sinks.console]
type = "console"
inputs = ["my_transform"]
encoding.codec = "json"
```

### Файл

```toml
[sinks.file]
type = "file"
inputs = ["my_transform"]
path = "/var/log/processed/events.log"
encoding.codec = "json"
```

### PostgreSQL

Отправка в базу данных:

```toml
[sinks.postgres]
type = "postgresql"
inputs = ["my_transform"]
endpoint = "postgresql://user:password@localhost:5432/logs"
table = "events"
```

Vector автоматически создаёт batch-запросы для эффективной вставки.

## VRL: язык трансформаций

VRL (Vector Remap Language) — это безопасный язык для обработки данных. Он не позволяет делать опасные операции (сетевые запросы, доступ к файловой системе), но достаточно мощный для любых трансформаций.

Основные операции:

```
# Доступ к полям
.field_name
.nested.field

# Присваивание
.new_field = "value"
.status_code = to_int!(.status)

# Условия
if .status >= 400 {
    .severity = "error"
} else {
    .severity = "info"
}

# Удаление полей
del(.sensitive_data)

# Работа со строками
.message = downcase(.message)
.ip = strip_whitespace(.ip)

# Работа с временем
.timestamp = parse_timestamp!(.time, "%Y-%m-%d %H:%M:%S")
```

## Практические паттерны для ИБ

### Сбор auth-логов с классификацией

```toml
[sources.auth_logs]
type = "file"
include = ["/var/log/auth.log"]

[transforms.parse_auth]
type = "remap"
inputs = ["auth_logs"]
source = '''
. |= parse_syslog!(.message)

# Классифицируем событие
if contains(.message, "Failed password") {
    .event_type = "login_failure"
    .severity = "warning"
} else if contains(.message, "Accepted") {
    .event_type = "login_success"
    .severity = "info"
} else if contains(.message, "session opened") {
    .event_type = "session_start"
    .severity = "info"
}
'''

[transforms.only_auth_events]
type = "filter"
inputs = ["parse_auth"]
condition = 'exists(.event_type)'
```

### Обнаружение подозрительной активности

```toml
[transforms.detect_bruteforce]
type = "remap"
inputs = ["parse_auth"]
source = '''
if .event_type == "login_failure" {
    # Помечаем как потенциально подозрительное
    .requires_investigation = true
    
    # Если IP внешний — повышаем severity
    if !starts_with(.source_ip, "192.168.") && !starts_with(.source_ip, "10.") {
        .severity = "high"
        .alert = "External brute-force attempt"
    }
}
'''
```

## Альтернативы Vector

__Fluent Bit__ — ещё один легковесный сборщик на C. Популярен в Kubernetes. Меньше возможностей трансформации, но проще в настройке.

__Filebeat__ — от Elastic, часть ELK-стека. Хорошо интегрирован с Elasticsearch, но привязан к экосистеме Elastic.

__Logstash__ — мощный, но тяжёлый (JVM). Используйте, если уже есть Java-инфраструктура и нужны сложные плагины.

__Fluentd__ — гибкий, много плагинов. Написан на Ruby, что влияет на производительность.

Vector выигрывает по соотношению производительности и функциональности. Для нового проекта — отличный выбор.

## Полезные ресурсы

- [Vector Documentation](https://vector.dev/docs/)
- [VRL Reference](https://vector.dev/docs/reference/vrl/)
- [Vector Examples](https://vector.dev/docs/reference/configuration/examples/)

## Практические задания

### Задание 2.1: Парсинг и обработка логов

Настройте Vector для обработки логов веб-сервера.

В директории `data/` находится файл `nginx_access.log` с логами в combined-формате. Ваша задача — создать конфигурацию Vector, которая:

1. Читает логи из файла
2. Парсит их с извлечением полей: IP, timestamp, method, path, status, size, user_agent
3. Добавляет поле `severity`: "error" для статусов >= 400, "info" для остальных
4. Выводит результат в консоль в JSON-формате

__Чеклист выполнения:__

- [ ] Создан файл `vector.toml` с конфигурацией
- [ ] Vector успешно парсит логи (нет ошибок в выводе)
- [ ] В JSON-выводе присутствуют все извлечённые поля
- [ ] Поле `severity` корректно выставляется

### Задание 2.2: Маршрутизация в PostgreSQL

Расширьте конфигурацию из задания 2.1:

1. Добавьте маршрутизацию: события с ошибками (status >= 400) и успешные запросы должны обрабатываться отдельно
2. Добавьте обогащение: для ошибок добавьте поле `requires_attention = true`
3. Отправьте все события в PostgreSQL (используйте базу из Блока 1)

__Требования к PostgreSQL:__

- Таблица `nginx_logs` с полями: timestamp, source_ip, method, path, status, size, user_agent, severity
- Vector должен подключаться к той же базе `security_logs`

__Чеклист выполнения:__

- [ ] Конфигурация содержит маршрутизацию по статусу
- [ ] Ошибки обогащаются дополнительными полями
- [ ] Данные успешно записываются в PostgreSQL
- [ ] В таблице `nginx_logs` появляются записи из лог-файла
