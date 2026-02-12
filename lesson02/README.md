# Блок 2. Сбор и маршрутизация логов

## Алерт и необходимость централизованного сбора

> Вторник, 14:23. Алексей только что закончил настройку локального стенда, когда в Slack-канале #security-alerts появилось новое сообщение от SIEM-системы: "Multiple failed login attempts detected on payment-gateway from external IP 203.0.113.42".
>
> Марина подошла к его рабочему месту. "Видишь проблему? Алерт пришёл, но у нас нет централизованного сбора логов. Денису пришлось вручную подключаться к серверу payment-gateway и смотреть логи. Это занимает время, а время в инциденте — критический ресурс."
>
> Алексей кивнул. "А что если таких серверов десятки? И логи в разных форматах?"
>
> "Именно", — Марина открыла терминал. — "Вот почему нам нужен сборщик логов. Vector собирает данные из всех источников — файлы, контейнеры, syslog — и отправляет в PostgreSQL. Один формат, одна точка входа. Когда случается инцидент, мы не тратим время на поиск логов — они уже в базе."
>
> Она показала на экран. "Сейчас у нас логи разбросаны: nginx пишет в Combined Log Format, приложения — в JSON, DNS-сервер — в BIND query log, фаервол — в CEF. Vector парсит всё это и приводит к единой структуре. Твоя задача — настроить парсеры для каждого формата."

---

## Проблема: логи везде, порядка нигде

Представьте типичную инфраструктуру компании: веб-серверы пишут логи в `/var/log/nginx/`, приложения — в свои файлы, системные события уходят в syslog, контейнеры выводят в stdout. Каждый источник использует свой формат. Когда случается инцидент, аналитику приходится подключаться к десяткам серверов, искать нужные файлы, разбираться с форматами.

Сборщик логов решает эту проблему: он собирает данные из разных источников, приводит к единому формату и отправляет в централизованное хранилище. Вместо "подключись к серверу и grep'ни логи" вы получаете "открой дашборд и найди всё в одном месте".

## Vector: современный сборщик логов

Vector — это инструмент для сбора, трансформации и отправки логов и метрик. Написан на Rust, что даёт высокую производительность при минимальном потреблении ресурсов.

Почему именно Vector:
__Производительность.__ Обрабатывает до 10 ТБ данных в день на одном сервере. Для сравнения: Logstash на тех же задачах потребляет в 10 раз больше памяти.

__Единый конфиг.__ Один TOML/YAML файл описывает весь pipeline. Не нужно изучать несколько инструментов.

__Богатый язык трансформаций.__ VRL (Vector Remap Language) позволяет парсить, фильтровать и обогащать данные без внешних скриптов.

__Надёжность.__ Буферизация на диске, at-least-once доставка, автоматическое переподключение.

## Установка Vector

Vector распространяется как Docker-образ. Для работы с заданиями этого блока вам понадобится образ версии `0.52.0-alpine`.

Для тестов можно установить Vector с [официального сайта](https://vector.dev/), но требуется VPN. Гораздо лучше для тренировок использовать [VRL Playground](https://playground.vrl.dev/).

### Скачивание образа

Выполните команду для скачивания образа:

```bash
docker pull timberio/vector:0.52.0-alpine
```

Проверьте, что образ успешно скачан:

```bash
docker images | grep vector
```

Вы должны увидеть строку с `timberio/vector` и тегом `0.52.0-alpine`.

### Проверка установки

Убедитесь, что Vector работает корректно:

```bash
docker run --rm timberio/vector:0.52.0-alpine --version
```

Команда должна вывести версию Vector (например, `0.52.0`).

> __Примечание:__ В заданиях этого блока мы используем конкретную версию образа (`0.52.0-alpine`) для обеспечения воспроизводимости результатов. Если вы используете `docker-compose.yml`, образ будет скачан автоматически при первом запуске.

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
# Парсим nginx combined log format
# Формат: IP - - [timestamp] "method path protocol" status size "referer" "user_agent"
. |= parse_regex!(
    .message,
    r'^(?P<source_ip>\S+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+[^"]+"\s+(?P<status>\d+)\s+(?P<size>\d+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

# Преобразуем типы
.status = to_int!(.status)
.size = to_int!(.size)

# Парсим timestamp
.timestamp = parse_timestamp!(.timestamp, format: "%d/%b/%Y:%H:%M:%S %z")
'''
```

Оператор `|=` добавляет извлечённые поля к событию. В regex используйте именованные группы `(?P<имя_поля>паттерн)` для извлечения полей.

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

## Форматы логов в FinanceFlow

В инфраструктуре FinanceFlow используются четыре типа логов, каждый со своим форматом:

### 1. Auth Events (JSON)

События аутентификации в формате JSON. Используются приложениями для логирования входов, выходов и неудачных попыток.

__Пример:__
```json
{"timestamp": "2024-03-08T03:47:22.456Z", "event_type": "login_success", "username": "dev_sergey", "source_ip": "192.168.1.100", "success": true, "details": {"method": "password", "user_agent": "Mozilla/5.0"}}
```

### 2. Nginx Logs (Combined Log Format)

Логи веб-сервера nginx в стандартном Combined Log Format.

__Пример:__
```
203.0.113.42 - - [01/Mar/2024:10:15:32 +0000] "GET /admin HTTP/1.1" 403 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
```

Формат: `IP - - [timestamp] "method path protocol" status size "referer" "user_agent"`

### 3. DNS Queries (BIND query log)

DNS-запросы в формате BIND query log.

__Пример:__
```
12-Mar-2024 14:23:45.123 client @0x7f9b2c001a00 192.168.1.100#54321 (x7kj2m9p.data-sync.xyz): query: x7kj2m9p.data-sync.xyz IN A +E(0)K (8.8.8.8)
```

Формат: `timestamp client @client_id source_ip#port (domain): query: domain IN TYPE flags (resolver)`

### 4. Firewall Events (CEF)

События фаервола в формате CEF (Common Event Format).

__Пример:__
```
Mar 01 10:15:32 fw-gateway CEF:0|FinanceFlow|Firewall|1.0|200|Connection block|7|src=203.0.113.42 dst=192.168.1.10 spt=45678 dpt=22 proto=TCP act=block reason=port_scan
```

Формат: `timestamp hostname CEF:version|vendor|product|version|event_id|action|severity|extensions`

## Практические задания

### Задание 2.1: Настройка генератора логов

Перед настройкой Vector нужно запустить генератор логов, который будет создавать события в реальном времени.

1. Изучите структуру проекта: генератор находится в `lesson02/app/generate_logs_realtime.py`
2. Создайте `docker-compose.yml` в директории `lesson02/` на основе эталонного решения
3. Запустите генератор логов и убедитесь, что файлы создаются в общем volume

__Чеклист выполнения:__

- [ ] Создан `docker-compose.yml` с сервисами `postgres`, `log-generator` и `vector`
- [ ] Генератор успешно запускается и создаёт файлы логов
- [ ] В директории `/logs` (в контейнере) появляются файлы: `auth_events.log`, `nginx_logs.log`, `dns_queries.log`, `firewall_events.log`

### Задание 2.2: Парсинг auth_events (JSON)

Настройте Vector для парсинга событий аутентификации в формате JSON.

1. Создайте конфигурацию `vector-configs/auth_events.toml` на основе шаблона
2. Реализуйте парсинг JSON из поля `.message`
3. Преобразуйте timestamp в стандартный формат
4. Добавьте поле `severity` на основе `event_type`
5. Настройте отправку в PostgreSQL в таблицу `auth_events`

__Пример входных данных:__
```json
{"timestamp": "2024-03-08T03:47:22.456Z", "event_type": "login_success", "username": "dev_sergey", "source_ip": "192.168.1.100", "success": true}
```

__Полный пример конфигурации:__

```toml
[sources.auth_logs]
type = "file"
include = ["/logs/auth_events.log"]
read_from = "beginning"

[transforms.parse_auth]
type = "remap"
inputs = ["auth_logs"]
source = '''
# Шаг 1: Парсим JSON из .message
# .message содержит строку с JSON, нужно распарсить её
. = parse_json!(.message)

# Шаг 2: Преобразуем timestamp
# timestamp в формате ISO 8601 (например, "2024-03-08T03:47:22.456Z")
# Формат "%+" означает ISO 8601
.timestamp = parse_timestamp!(.timestamp, format: "%+")

# Шаг 3: Добавляем severity на основе event_type
if .event_type == "login_failure" {
    .severity = "warning"
} else if .event_type == "login_success" {
    .severity = "info"
} else {
    .severity = "info"
}

# Шаг 4: Удаляем служебные поля Vector
# Vector добавляет служебные поля .file, .host, .source_type
del(.file)
del(.host)
del(.source_type)
'''

[sinks.postgres_auth]
type = "postgres"
inputs = ["parse_auth"]
endpoint = "postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
table = "auth_events"
healthcheck.enabled = true
```

__Чеклист выполнения:__

- [ ] JSON успешно парсится из `.message`
- [ ] Timestamp корректно преобразуется
- [ ] Поле `severity` добавляется на основе `event_type`
- [ ] Данные записываются в PostgreSQL

### Задание 2.3: Парсинг nginx_logs (Combined Log Format)

Настройте Vector для парсинга логов nginx в Combined Log Format.

1. Создайте конфигурацию `vector-configs/nginx_logs.toml`
2. Реализуйте парсинг с помощью `parse_regex!` для извлечения всех полей
3. Преобразуйте `status` и `size` в числа
4. Парсите timestamp в формате nginx
5. Добавьте `severity` на основе HTTP статуса

__Чеклист выполнения:__

- [ ] Все поля успешно извлекаются из лога
- [ ] Типы данных корректно преобразуются
- [ ] Timestamp парсится правильно
- [ ] Данные записываются в PostgreSQL

### Задание 2.4: Парсинг dns_queries (BIND query log)

Настройте Vector для парсинга DNS-запросов в формате BIND query log.

1. Создайте конфигурацию `vector-configs/dns_queries.toml`
2. Реализуйте парсинг BIND формата с помощью regex
3. Извлеките все поля: timestamp, source_ip, source_port, query_domain, query_type, resolver
4. Преобразуйте `source_port` в число
5. Парсите timestamp в формате BIND

__Пример входных данных:__
```
12-Mar-2024 14:23:45.123 client @0x7f9b2c001a00 192.168.1.100#54321 (x7kj2m9p.data-sync.xyz): query: x7kj2m9p.data-sync.xyz IN A +E(0)K (8.8.8.8)
```

__Пример VRL кода для парсинга:__

```toml
source = '''
# Извлекаем основные поля из BIND формата
# Формат: timestamp client @0x... source_ip#port (domain): query: domain IN TYPE +flags (resolver)
. |= parse_regex!(
    .message,
    r'^(?P<timestamp>[^\s]+\s+[^\s]+\s+[^\s]+)\s+client\s+@0x[^\s]+\s+(?P<source_ip>[^#]+)#(?P<source_port>\d+)\s+\((?P<query_domain>[^)]+)\):\s+query:\s+\S+\s+IN\s+(?P<query_type>\S+)\s+[^\s]+\s*(?:\((?P<resolver>[^)]+)\))?'
)

# Преобразуем source_port в число
.source_port = to_int!(.source_port)

# Парсим timestamp
# Формат BIND: 12-Mar-2024 14:23:45.123
.timestamp = parse_timestamp!(.timestamp, format: "%d-%b-%Y %H:%M:%S%.f")

# Добавляем severity (для DNS обычно "info")
.severity = "info"

# Удаляем служебные поля
del(.file)
del(.host)
del(.source_type)
del(.message)
'''
```

__Чеклист выполнения:__

- [ ] Все поля успешно извлекаются
- [ ] Timestamp парсится корректно
- [ ] Данные записываются в PostgreSQL

### Задание 2.5: Парсинг firewall_events (CEF)

Настройте Vector для парсинга событий фаервола в формате CEF.

1. Создайте конфигурацию `vector-configs/firewall_events.toml`
2. Реализуйте парсинг CEF формата
3. Извлеките основные поля из extensions с помощью `parse_key_value!`
4. Преобразуйте `severity` из числа в строку
5. Парсите timestamp в формате CEF

__Пример входных данных:__
```
Mar 01 10:15:32 fw-gateway CEF:0|FinanceFlow|Firewall|1.0|200|Connection block|7|src=203.0.113.42 dst=192.168.1.10 spt=45678 dpt=22 proto=TCP act=block reason=port_scan
```

__Пример VRL кода для парсинга:__

```toml
source = '''
# Шаг 1: Извлекаем основные поля и extensions
# Формат: timestamp hostname CEF:version|vendor|product|version|event_id|action|severity|extensions
. |= parse_regex!(
    .message,
    r'^(?P<timestamp>[^\s]+\s+[^\s]+\s+[^\s]+)\s+\S+\s+CEF:\d+\|[^|]+\|[^|]+\|[^|]+\|[^|]+\|[^|]+\|(?P<severity>\d+)\|(?P<extensions>.*)'
)

# Шаг 2: Парсим timestamp
# Формат CEF: Mar 01 10:15:32
.timestamp = parse_timestamp!(.timestamp, format: "%b %d %H:%M:%S")

# Шаг 3: Парсим extensions (key=value пары)
# extensions содержат пары вида "src=203.0.113.42 dst=192.168.1.10 ..."
.extensions = parse_key_value!(.extensions, field_delimiter: " ", key_value_delimiter: "=")

# Шаг 4: Извлекаем поля из extensions
.source_ip = .extensions.src
.dest_ip = .extensions.dst
.source_port = to_int!(.extensions.spt)
.dest_port = to_int!(.extensions.dpt)
.protocol = .extensions.proto
.action = .extensions.act
.reason = .extensions.reason

# Шаг 5: Преобразуем severity из числа в строку
.severity_num = to_int!(.severity)
if .severity_num >= 7 {
    .severity = "error"
} else if .severity_num >= 4 {
    .severity = "warning"
} else {
    .severity = "info"
}

# Шаг 6: Удаляем временные поля
del(.extensions)
del(.severity_num)
del(.file)
del(.host)
del(.source_type)
del(.message)
'''
```

__Чеклист выполнения:__

- [ ] CEF формат успешно парсится
- [ ] Extensions корректно извлекаются
- [ ] Severity преобразуется правильно
- [ ] Данные записываются в PostgreSQL

### Задание 2.6: Объединение всех конфигураций

Создайте единый файл `vector-configs/vector.toml`, который объединяет все четыре конфигурации и отправляет данные в соответствующие таблицы PostgreSQL.

__Чеклист выполнения:__

- [ ] Все четыре источника настроены
- [ ] Все четыре трансформации работают корректно
- [ ] Данные записываются во все четыре таблицы PostgreSQL
- [ ] Проверено наличие данных в таблицах: `auth_events`, `nginx_logs`, `dns_queries`, `firewall_events`

## Что дальше?

После успешной настройки Vector вы сможете:
- Централизованно собирать логи из разных источников
- Парсить различные форматы логов
- Отправлять данные в PostgreSQL для последующего анализа

В следующем блоке мы научимся оптимизировать хранение данных и создавать индексы для быстрого поиска индикаторов атаки.
