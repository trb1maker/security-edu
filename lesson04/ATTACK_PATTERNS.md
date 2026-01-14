# Справочник паттернов атак

Этот документ описывает общие паттерны атак и примеры SQL-запросов для их обнаружения. Используйте его как справочник при выполнении практических заданий.

**Важно:** В этом документе нет конкретных значений из датасета курса (IP-адресов, доменов, имён пользователей). Ваша задача — найти эти значения самостоятельно с помощью SQL-запросов.

## RECON (Разведка)

### Что это такое

Разведка — это первый этап атаки, когда злоумышленник собирает информацию о целевой инфраструктуре. Цель — понять, какие системы работают, какие технологии используются, какие уязвимости можно эксплуатировать.

### Как проходит атака

1. **Веб-сканирование:**
   - Злоумышленник проверяет стандартные пути административных панелей (`/admin`, `/wp-admin`)
   - Ищет конфигурационные файлы (`/.env`, `/.git/config`)
   - Анализирует ответы сервера (403 = путь существует, 404 = путь не существует)

2. **Сканирование портов:**
   - Проверяет, какие порты открыты на целевых системах
   - Использует инструменты типа Nmap для автоматизации
   - Анализирует ответы: открыт порт → сервис доступен

3. **Сбор информации:**
   - Определяет версии сервисов и операционных систем
   - Ищет уязвимости в известных версиях

### Что искать в логах

**В веб-логах (nginx_logs):**
- Множество запросов к подозрительным путям (`/admin`, `/.env`, `/wp-admin`)
- HTTP-коды 403 (Forbidden) или 404 (Not Found)
- Подозрительные User-Agent (содержащие "Nmap", "Scanner", "Bot")

**В логах фаервола (firewall_events):**
- Множество блокированных соединений с одного IP
- Попытки подключения к разным портам одной цели
- Порты сканирования: 22 (SSH), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis)

### Примеры SQL-запросов

```sql
-- Поиск подозрительных путей в веб-логах
SELECT 
    source_ip,
    path,
    status,
    COUNT(*) as attempts
FROM nginx_logs
WHERE status IN (403, 404)
  AND (path LIKE '%/admin%' 
       OR path LIKE '%/.env%' 
       OR path LIKE '%/wp-admin%'
       OR path LIKE '%/.git%')
  AND timestamp >= '2024-03-01'  -- Период разведки
  AND timestamp < '2024-03-04'
GROUP BY source_ip, path, status
HAVING COUNT(*) > 5
ORDER BY attempts DESC;

-- Обнаружение сканирования портов
SELECT 
    source_ip,
    dest_ip,
    COUNT(DISTINCT dest_port) as unique_ports,
    STRING_AGG(DISTINCT dest_port::text, ', ' ORDER BY dest_port::text) as ports
FROM firewall_events
WHERE action = 'BLOCK'
  AND timestamp >= '2024-03-01'
  AND timestamp < '2024-03-04'
GROUP BY source_ip, dest_ip
HAVING COUNT(DISTINCT dest_port) > 5
ORDER BY unique_ports DESC;
```

### Индикаторы компрометации

- Один IP обращается к множеству подозрительных путей
- Один IP пытается подключиться к множеству портов
- Подозрительные User-Agent в веб-логах
- Множество блокированных соединений с одного IP

---

## BRUTEFORCE (Подбор паролей)

### Что это такое

Brute-force — это метод атаки, при котором злоумышленник систематически перебирает пароли для получения доступа к учётной записи. Цель — получить доступ к системе через слабый пароль.

### Как проходит атака

1. **Выбор цели:**
   - Злоумышленник выбирает пользователя или сервис для атаки
   - Использует информацию из социальных сетей для составления словаря паролей

2. **Автоматизация:**
   - Использует инструменты (Hydra, Medusa) или скрипты для автоматизации
   - Перебирает пароли из словарей (`rockyou.txt`, `common-passwords.txt`)
   - Замедляет скорость атаки для обхода rate limiting

3. **Методы:**
   - **Классический brute-force:** один username, множество паролей
   - **Password spraying:** один пароль, множество username
   - **Credential stuffing:** использование украденных credentials

### Что искать в логах

**В логах аутентификации (auth_events):**
- Множество событий `login_failure` с одного IP за короткий период
- Один и тот же username, разные пароли
- Событие `login_success` после серии неудач — признак успешного взлома
- Подозрительные User-Agent (`python-requests`, автоматизированные инструменты)

**Временные характеристики:**
- Интервал между попытками: миллисекунды — секунды (автоматизация)
- Общая длительность: минуты — часы
- Типичный порог: >5-10 неудачных попыток за 5 минут

### Примеры SQL-запросов

```sql
-- TOP IP по неудачным попыткам входа
SELECT 
    source_ip,
    COUNT(*) as failed_attempts,
    COUNT(DISTINCT username) as attacked_users,
    MIN(timestamp) as first_attempt,
    MAX(timestamp) as last_attempt
FROM auth_events
WHERE event_type = 'login_failure'
  AND timestamp >= '2024-03-04'  -- Период brute-force
  AND timestamp < '2024-03-08'
GROUP BY source_ip
HAVING COUNT(*) > 50
ORDER BY failed_attempts DESC;

-- Пользователи, подвергшиеся атаке
SELECT 
    username,
    source_ip,
    COUNT(*) as failed_attempts,
    MIN(timestamp) as first_attempt,
    MAX(timestamp) as last_attempt
FROM auth_events
WHERE event_type = 'login_failure'
  AND timestamp >= '2024-03-04'
  AND timestamp < '2024-03-08'
GROUP BY username, source_ip
HAVING COUNT(*) > 10
ORDER BY failed_attempts DESC;
```

### Индикаторы компрометации

- Множество `login_failure` с одного IP
- Один username атакуется с одного IP
- Автоматизированные User-Agent
- Всплеск неудачных попыток в короткий период

---

## COMPROMISE (Компрометация)

### Что это такое

Компрометация — это момент, когда злоумышленник успешно получает доступ к системе после brute-force атаки или эксплуатации уязвимости. Это критический этап, после которого злоумышленник может выполнять действия от имени скомпрометированного пользователя.

### Как проходит атака

1. **Момент компрометации:**
   - После серии неудачных попыток злоумышленник находит правильный пароль
   - Успешно входит в систему
   - Часто происходит в нерабочее время для маскировки

2. **Первые действия:**
   - Проверяет уровень доступа
   - Изучает окружение системы
   - Ищет интересные файлы (ключи SSH, конфигурации БД)
   - Устанавливает backdoor для постоянного доступа

### Что искать в логах

**В логах аутентификации (auth_events):**
- Событие `login_success` после серии `login_failure`
- Тот же IP и username, что использовались для brute-force
- Вход в нерабочее время (признак компрометации)
- Короткий интервал между последней неудачей и успехом

**Временные характеристики:**
- Время между последней неудачей и успехом: минуты — часы
- Часто происходит в нерабочее время (ночь, выходные)

### Примеры SQL-запросов

```sql
-- Обнаружение успешного входа после неудач
WITH attempts AS (
    SELECT 
        timestamp,
        username,
        source_ip,
        success,
        LAG(success) OVER (
            PARTITION BY username, source_ip 
            ORDER BY timestamp
        ) as prev_success,
        LAG(timestamp) OVER (
            PARTITION BY username, source_ip 
            ORDER BY timestamp
        ) as prev_time
    FROM auth_events
    WHERE timestamp >= '2024-03-08'  -- День компрометации
      AND timestamp < '2024-03-09'
)
SELECT 
    timestamp as compromise_time,
    username,
    source_ip,
    prev_time as last_failed_attempt,
    timestamp - prev_time as time_to_crack
FROM attempts
WHERE success = true 
  AND prev_success = false
  AND timestamp - prev_time < INTERVAL '1 hour'
ORDER BY timestamp;
```

### Индикаторы компрометации

- Успешный вход после серии неудач
- Тот же IP, что использовался для brute-force
- Вход в нерабочее время
- Короткий интервал между неудачей и успехом

---

## LATERAL MOVEMENT (Горизонтальное перемещение)

### Что это такое

Lateral movement — это техника, при которой злоумышленник перемещается по внутренней сети после первичной компрометации. Цель — расширить доступ и достичь более ценных целей (серверы баз данных, production-окружение).

### Как проходит атака

1. **Кража учётных данных:**
   - Злоумышленник использует украденные пароли или SSH-ключи
   - Извлекает пароли из конфигурационных файлов
   - Использует инструменты (mimikatz) для извлечения паролей из памяти

2. **Перемещение по сети:**
   - Использует украденные credentials для доступа к другим системам
   - Пробует те же пароли на других системах (password reuse)
   - Подключается к базам данных для поиска дополнительных credentials

3. **Новые хосты:**
   - Входы с внутренних IP-адресов (например, `10.0.0.x`)
   - Доступ к серверам баз данных (порты 3306, 5432, 6379)
   - Последовательные входы на разные системы за короткое время

### Что искать в логах

**В логах аутентификации (auth_events):**
- Вход пользователя с IP-адреса, с которого он не входил ранее (за последние 30 дней)
- Входы с внутренних IP-адресов после компрометации
- Последовательные входы на несколько систем за короткое время
- Доступ к базам данных (порты 3306, 5432, 6379)

**Временные характеристики:**
- Интервал между перемещениями: минуты — часы
- Общая длительность: часы — дни
- Признак: первый вход с данного IP за 30+ дней

### Примеры SQL-запросов

```sql
-- Обнаружение входов с новых хостов
WITH 
-- Нормальные хосты пользователя за последние 30 дней (кроме последнего дня)
normal_hosts AS (
    SELECT DISTINCT username, source_ip
    FROM auth_events
    WHERE success = true
      AND timestamp BETWEEN 
          (SELECT MAX(timestamp) - INTERVAL '30 days' FROM auth_events)
          AND 
          (SELECT MAX(timestamp) - INTERVAL '1 day' FROM auth_events)
),
-- Входы за последние сутки
recent_logins AS (
    SELECT *
    FROM auth_events
    WHERE success = true
      AND timestamp > (SELECT MAX(timestamp) - INTERVAL '1 day' FROM auth_events)
)
-- Новые хосты = lateral movement кандидаты
SELECT 
    r.timestamp,
    r.username,
    r.source_ip as new_host,
    'LATERAL_MOVEMENT_CANDIDATE' as alert_type
FROM recent_logins r
LEFT JOIN normal_hosts n 
    ON r.username = n.username AND r.source_ip = n.source_ip
WHERE n.source_ip IS NULL  -- хост не в списке "нормальных"
ORDER BY r.timestamp;
```

### Индикаторы компрометации

- Вход с нового IP-адреса (первый раз за 30+ дней)
- Входы с внутренних IP после компрометации
- Последовательные входы на разные системы
- Доступ к базам данных с необычных хостов

---

## C2_SETUP (Установка канала управления)

### Что это такое

C2 (Command & Control) — это инфраструктура для удалённого управления заражёнными системами. После компрометации злоумышленник устанавливает malware, который поддерживает связь с командным сервером для передачи команд и получения результатов.

### Как проходит атака

1. **Установка malware:**
   - Злоумышленник загружает и запускает backdoor на скомпрометированных системах
   - Настраивает автозапуск для постоянства
   - Маскирует процесс под легитимный системный сервис

2. **DGA (Domain Generation Algorithm):**
   - Malware использует алгоритм генерации доменов
   - Каждый день генерируется новый список доменов
   - Злоумышленник регистрирует один из доменов
   - Malware перебирает домены, пока не найдёт активный C2-сервер

3. **DNS-туннелирование:**
   - Команды передаются через DNS-запросы (закодированы в поддоменах)
   - Ответы содержат команды для выполнения
   - Обходит firewall, так как DNS обычно разрешён

### Что искать в логах

**В DNS-логах (dns_queries):**
- Запросы к доменам с высокой энтропией (случайные символы)
- Множество запросов к несуществующим доменам (NXDOMAIN)
- Очень длинные доменные имена (>30 символов)
- Нетипичные TLD (`.xyz`, `.top`, `.club`)
- Паттерн: много неудачных DNS → один успешный → сетевая активность

**Характеристики DGA-доменов:**
- Длина поддомена: 8-15 символов
- Состав: случайные буквы и цифры
- Высокая энтропия (>3.5)
- Отсутствие словарных слов

### Примеры SQL-запросов

```sql
-- Поиск DGA-доменов (высокая энтропия)
SELECT 
    query_domain,
    source_ip,
    COUNT(*) as queries,
    -- Простая эвристика: длина поддомена и количество цифр
    LENGTH(SPLIT_PART(query_domain, '.', 1)) as subdomain_length,
    LENGTH(REGEXP_REPLACE(query_domain, '[^0-9]', '', 'g')) as digit_count
FROM dns_queries
WHERE timestamp >= '2024-03-12'  -- Период C2_SETUP
  AND timestamp < '2024-03-14'
  AND LENGTH(SPLIT_PART(query_domain, '.', 1)) > 10
  AND LENGTH(REGEXP_REPLACE(query_domain, '[^0-9]', '', 'g')) > 2
GROUP BY query_domain, source_ip
HAVING COUNT(*) > 5
ORDER BY queries DESC;

-- Поиск доменов с нетипичными TLD
SELECT 
    query_domain,
    COUNT(*) as queries
FROM dns_queries
WHERE timestamp >= '2024-03-12'
  AND timestamp < '2024-03-14'
  AND (query_domain LIKE '%.xyz'
       OR query_domain LIKE '%.top'
       OR query_domain LIKE '%.club')
GROUP BY query_domain
HAVING COUNT(*) > 10
ORDER BY queries DESC;
```

### Индикаторы компрометации

- Домены с высокой энтропией (случайные символы)
- Множество NXDOMAIN-ответов
- Нетипичные TLD
- Запросы из внутренней сети к внешним доменам

---

## EXFILTRATION (Утечка данных)

### Что это такое

Exfiltration — это финальный этап атаки, когда злоумышленник выводит украденные данные за периметр организации. Цель — получить доступ к конфиденциальной информации (исходный код, базы данных, credentials).

### Как проходит атака

1. **Подготовка данных:**
   - Злоумышленник собирает интересующие данные
   - Архивирует данные (tar, zip) для уменьшения размера
   - Шифрует архив для маскировки содержимого
   - Разбивает на части для обхода ограничений размера

2. **Методы вывода:**
   - **HTTPS:** загружает данные через API на внешний сервер
   - **DNS-туннелирование:** передаёт данные через большие DNS TXT-записи
   - **Облачные хранилища:** загружает в Dropbox, Google Drive через API

3. **Маскировка:**
   - Использует легитимные порты (443 для HTTPS)
   - Имитирует нормальный веб-трафик
   - Выводит данные в нерабочее время

### Что искать в логах

**В веб-логах (nginx_logs):**
- Необычно большие ответы API (>1MB)
- Запросы к API-эндпоинтам с большими ответами
- Активность в нерабочее время
- Исходящий трафик к внешним IP

**В логах фаервола (firewall_events):**
- Большой исходящий трафик с рабочей станции
- Соединения на нестандартные порты (не 80/443)
- Подключения к IP без PTR-записи
- Активность в нерабочее время

**Временные характеристики:**
- Большие объёмы данных за короткое время
- Или медленный вывод малыми порциями (low and slow)

### Примеры SQL-запросов

```sql
-- Поиск необычно больших ответов API
SELECT 
    source_ip,
    path,
    status,
    size,
    timestamp
FROM nginx_logs
WHERE size > 1000000  -- > 1MB
  AND path LIKE '/api/%'
  AND status = 200
  AND timestamp >= '2024-03-13'  -- Период exfiltration
  AND timestamp < '2024-03-15'
ORDER BY size DESC;

-- Поиск большого исходящего трафика
SELECT 
    source_ip,
    dest_ip,
    SUM(bytes_sent) as total_bytes_sent,
    COUNT(*) as connections
FROM firewall_events
WHERE action = 'ALLOW'
  AND bytes_sent > 100000  -- > 100KB за соединение
  AND timestamp >= '2024-03-13'
  AND timestamp < '2024-03-15'
GROUP BY source_ip, dest_ip
HAVING SUM(bytes_sent) > 10000000  -- > 10MB всего
ORDER BY total_bytes_sent DESC;
```

### Индикаторы компрометации

- Необычно большие ответы API (>1MB)
- Исходящий трафик к внешним IP
- Активность в нерабочее время
- Большие DNS TXT-запросы (DNS-туннелирование)

---

## Построение timeline атаки

### Зачем это нужно

Timeline помогает понять последовательность событий и связать разрозненные индикаторы в единую картину атаки. Это критически важно для понимания масштаба инцидента и оценки ущерба.

### Как строить timeline

1. **Соберите события из всех источников:**
   - auth_events (входы, выходы)
   - nginx_logs (веб-активность)
   - firewall_events (сетевые соединения)
   - dns_queries (DNS-запросы)

2. **Объедините по времени:**
   - Используйте UNION ALL для объединения событий
   - Сортируйте по timestamp
   - Добавьте метку источника для каждого события

3. **Определите этапы:**
   - RECON: сканирование и разведка
   - BRUTEFORCE: подбор паролей
   - COMPROMISE: успешный вход
   - LATERAL: перемещение по сети
   - C2_SETUP: установка канала управления
   - EXFIL: утечка данных

### Пример SQL-запроса для timeline

```sql
-- Построение timeline для подозрительного IP
WITH target_ip AS (SELECT 'YOUR_SUSPICIOUS_IP'::VARCHAR as ip),

auth_timeline AS (
    SELECT 
        timestamp,
        'AUTH' as source,
        CASE 
            WHEN success THEN 'login_success' 
            ELSE 'login_failure' 
        END as event_type,
        username || ' from ' || source_ip as details
    FROM auth_events, target_ip
    WHERE source_ip = target_ip.ip
      AND timestamp >= '2024-03-01'
      AND timestamp < '2024-03-15'
),

nginx_timeline AS (
    SELECT 
        timestamp,
        'NGINX' as source,
        CASE 
            WHEN status >= 400 THEN 'error'
            ELSE 'request'
        END as event_type,
        path || ' (' || status || ')' as details
    FROM nginx_logs, target_ip
    WHERE source_ip = target_ip.ip
      AND timestamp >= '2024-03-01'
      AND timestamp < '2024-03-15'
),

firewall_timeline AS (
    SELECT 
        timestamp,
        'FIREWALL' as source,
        action as event_type,
        dest_ip || ':' || dest_port as details
    FROM firewall_events, target_ip
    WHERE source_ip = target_ip.ip
      AND timestamp >= '2024-03-01'
      AND timestamp < '2024-03-15'
),

dns_timeline AS (
    SELECT 
        timestamp,
        'DNS' as source,
        query_type as event_type,
        query_domain as details
    FROM dns_queries, target_ip
    WHERE source_ip = target_ip.ip
      AND timestamp >= '2024-03-01'
      AND timestamp < '2024-03-15'
)

-- Объединённый timeline
SELECT * FROM auth_timeline
UNION ALL SELECT * FROM nginx_timeline
UNION ALL SELECT * FROM firewall_timeline
UNION ALL SELECT * FROM dns_timeline
ORDER BY timestamp;
```

---

## Общие рекомендации

### Как искать индикаторы

1. **Начните с агрегаций:**
   - Найдите TOP IP по количеству событий
   - Определите временные паттерны (когда происходят атаки)

2. **Используйте оконные функции:**
   - LAG/LEAD для анализа последовательностей
   - ROW_NUMBER для поиска первых/последних событий

3. **Коррелируйте данные:**
   - Объединяйте события из разных источников
   - Ищите связи между IP, пользователями, доменами

4. **Стройте timeline:**
   - Объединяйте события по времени
   - Определяйте этапы атаки
   - Находите причинно-следственные связи

### Типичные ошибки

- **Игнорирование временных границ:** Всегда фильтруйте по периоду атаки (дни 61-74)
- **Фокус только на одном источнике:** Атака проявляется во всех типах логов
- **Игнорирование внутренних IP:** После компрометации злоумышленник использует внутренние IP
- **Недооценка DNS:** DNS-туннелирование — распространённый метод обхода firewall

### Полезные SQL-приёмы

- **CTE (WITH):** Структурируйте сложные запросы
- **Оконные функции:** Анализируйте последовательности событий
- **JOIN:** Коррелируйте данные из разных таблиц
- **UNION ALL:** Объединяйте события для timeline

---

## Связь с MITRE ATT&CK

Эта атака демонстрирует следующие техники из MITRE ATT&CK:

- **T1595** — Active Scanning (RECON)
- **T1110** — Brute Force (BRUTEFORCE)
- **T1078** — Valid Accounts (COMPROMISE)
- **T1021** — Remote Services (LATERAL MOVEMENT)
- **T1071** — Application Layer Protocol (C2_SETUP)
- **T1041** — Exfiltration Over C2 Channel (EXFILTRATION)

Подробнее: [MITRE ATT&CK Framework](https://attack.mitre.org/)
