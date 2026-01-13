# Блок 4. SQL-аналитика для ИБ

## Введение: SQL как язык расследований

SQL — это не просто способ достать данные из базы. Для аналитика ИБ это инструмент расследования инцидентов. Хорошо написанный запрос может за секунды найти то, что вручную искали бы часами.

В этом блоке мы научимся:

- Находить аномалии в потоке событий
- Обнаруживать паттерны атак (brute-force, сканирование, lateral movement)
- Коррелировать события из разных источников
- Строить timeline инцидента

__Основной инструмент:__ DuckDB (можно использовать PostgreSQL).

## Типы атак и их следы

Прежде чем писать запросы, нужно понимать, что мы ищем. Вот основные типы атак, которые мы будем обнаруживать:

### Brute-Force (подбор паролей)

__Цель злоумышленника:__ Получить доступ к учётной записи, подобрав пароль.

__Действия:__

1. Злоумышленник выбирает цель (пользователя или сервис)
2. Использует словарь паролей или генератор
3. Автоматически отправляет сотни/тысячи попыток входа
4. При успехе — получает доступ к системе

__Следы в логах:__

- Множество событий `login_failed` с одного IP за короткий период
- Один и тот же username, разные пароли (классический brute-force)
- Один пароль, разные username (password spraying)
- Событие `login_success` после серии неудач — признак успешного взлома

__Временные характеристики:__

- Интервал между попытками: миллисекунды — секунды (автоматизация)
- Общая длительность: минуты — часы
- Типичный порог: >5-10 неудачных попыток за 5 минут

### Сканирование портов (Port Scanning)

__Цель злоумышленника:__ Разведка — узнать, какие сервисы работают на целевой системе.

__Действия:__

1. Злоумышленник выбирает цель (IP или диапазон)
2. Отправляет пакеты на разные порты (SYN, connect, UDP)
3. Анализирует ответы: открыт, закрыт, фильтруется
4. Составляет карту сервисов для дальнейшей атаки

__Следы в логах:__

- Множество соединений с одного IP на разные порты одной цели
- Соединения на нестандартные порты (не 80, 443, 22)
- Много отклонённых соединений (rejected/dropped в firewall)
- Короткие соединения без передачи данных

__Временные характеристики:__

- Интервал между пакетами: миллисекунды (быстрое сканирование) — секунды (скрытное)
- Общая длительность: секунды — минуты
- Типичный порог: >10-20 разных портов за минуту

### Lateral Movement (горизонтальное перемещение)

__Цель злоумышленника:__ Расширить доступ в сети после первичной компрометации.

__Действия:__

1. Злоумышленник уже внутри сети (скомпрометировал один хост)
2. Собирает учётные данные (mimikatz, кеш паролей)
3. Пробует эти данные на других хостах
4. Перемещается к более ценным целям (серверы, контроллеры домена)

__Следы в логах:__

- Вход пользователя с нового/нетипичного хоста
- Вход в нерабочее время
- Последовательные входы на несколько систем за короткое время
- Использование административных учёток с рабочих станций

__Временные характеристики:__

- Интервал между перемещениями: минуты — часы
- Общая длительность: часы — дни
- Признак: первый вход с данного source_ip за 30+ дней

### Command & Control (C2) через DNS

__Цель злоумышленника:__ Установить скрытый канал связи с заражённой машиной.

__Действия:__

1. Malware на заражённой машине генерирует DNS-запросы
2. Данные кодируются в поддоменах (data.evil.com)
3. C2-сервер отвечает командами через DNS-ответы
4. Обходит firewall, так как DNS обычно разрешён

__Следы в логах:__

- Запросы к несуществующим доменам (NXDOMAIN)
- Очень длинные доменные имена (>30 символов)
- Высокая энтропия в имени домена (случайные символы)
- Частые запросы к одному домену 2-3 уровня
- Запросы к недавно зарегистрированным доменам

__Временные характеристики:__

- Периодические запросы: каждые N секунд/минут (heartbeat)
- Всплески при передаче данных

### DGA (Domain Generation Algorithm)

__Цель злоумышленника:__ Обеспечить устойчивую связь malware с C2-сервером.

__Действия:__

1. Malware использует алгоритм генерации доменов
2. Каждый день/час генерируется новый список доменов
3. Злоумышленник регистрирует один из доменов
4. Malware перебирает домены, пока не найдёт активный C2

__Следы в логах:__

- Множество NXDOMAIN-ответов (домены не существуют)
- Домены с высокой энтропией: `x7kj2m9p.com`, `qw3rt1y8.net`
- Нетипичные TLD: `.top`, `.xyz`, `.club`
- Паттерн: много неудачных DNS → один успешный → сетевая активность

__Характеристики DGA-доменов:__

- Длина: обычно 8-15 символов
- Состав: случайные буквы и цифры
- Отсутствие словарных слов

### Data Exfiltration (вывод данных)

__Цель злоумышленника:__ Вывести украденные данные за периметр.

__Действия:__

1. Злоумышленник собрал ценные данные
2. Архивирует и шифрует для маскировки
3. Выводит через разрешённые каналы (HTTPS, DNS, облачные хранилища)
4. Использует нестандартные порты или протоколы

__Следы в логах:__

- Большой исходящий трафик с рабочей станции
- Соединения на нестандартные порты (не 80/443)
- Подключения к IP без PTR-записи
- Активность в нерабочее время
- DNS-туннелирование (большие TXT-запросы)

__Временные характеристики:__

- Большие объёмы данных за короткое время
- Или медленный вывод малыми порциями (low and slow)

## Занятие 4.1: Базовая аналитика событий безопасности

### Агрегации — основа любой аналитики

Самый частый вопрос аналитика: "Сколько?" — событий, попыток, IP-адресов.

```sql
-- Сколько всего событий по типам?
FROM auth_events
SELECT event_type, COUNT(*) as cnt
GROUP BY ALL
ORDER BY cnt DESC;

-- Сколько уникальных IP пытались войти?
SELECT COUNT(DISTINCT source_ip) as unique_ips
FROM auth_events
WHERE success = false;
```

### TOP-N анализ: ищем аномалии

"Кто больше всех?" — первый шаг к обнаружению brute-force.

```sql
-- TOP-10 IP по неудачным попыткам входа
-- Ищем: источники brute-force атак
FROM auth_events
SELECT source_ip, COUNT(*) as failed_attempts
WHERE success = false
GROUP BY ALL
ORDER BY failed_attempts DESC
LIMIT 10;

-- TOP пользователей с высоким процентом неудач
-- Ищем: жертв brute-force или заблокированные учётки
FROM auth_events
SELECT 
    username,
    COUNT(*) as total_attempts,
    SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful,
    SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) as failed,
    ROUND(100.0 * SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) / COUNT(*), 1) as fail_rate
GROUP BY ALL
HAVING COUNT(*) > 10
ORDER BY fail_rate DESC
LIMIT 10;
```

### Временные ряды: когда происходят атаки?

```sql
-- Распределение по часам суток
-- Ищем: активность в нерабочее время (признак компрометации)
FROM auth_events
SELECT 
    EXTRACT(HOUR FROM timestamp) as hour,
    COUNT(*) as events,
    SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) as failed
GROUP BY ALL
ORDER BY hour;

-- Почасовая динамика за сутки
FROM auth_events
SELECT 
    DATE_TRUNC('hour', timestamp) as hour,
    COUNT(*) as events
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY ALL
ORDER BY hour;
```

### Выявление всплесков: статистические аномалии

```sql
-- Найти часы с аномально высокой активностью
-- Ищем: начало атаки или сбой системы
WITH hourly_stats AS (
    FROM auth_events
    SELECT 
        DATE_TRUNC('hour', timestamp) as hour,
        COUNT(*) as events
    GROUP BY ALL
),
avg_stats AS (
    SELECT AVG(events) as avg_events, STDDEV(events) as std_events
    FROM hourly_stats
)
FROM hourly_stats, avg_stats
SELECT hour, events, 
       ROUND((events - avg_events) / std_events, 2) as z_score
WHERE events > avg_events + 2 * std_events
ORDER BY events DESC;
```

## Занятие 4.2: Оконные функции для анализа последовательностей

### Что такое оконные функции?

Обычные агрегаты схлопывают строки. Оконные функции сохраняют все строки, добавляя вычисленные поля.

```sql
-- Для каждого события: сколько всего событий с этого IP
SELECT 
    *,
    COUNT(*) OVER (PARTITION BY source_ip) as ip_total_events
FROM auth_events;
```

### LAG и LEAD: анализ последовательностей

__Обнаружение Brute-Force:__

```sql
-- Шаг 1: добавляем контекст предыдущего события
-- Ищем: успешный вход сразу после неудачного (взлом!)
WITH events_with_context AS (
    FROM auth_events
    SELECT 
        *,
        LAG(success) OVER (
            PARTITION BY username, source_ip 
            ORDER BY timestamp
        ) as prev_success,
        LAG(timestamp) OVER (
            PARTITION BY username, source_ip 
            ORDER BY timestamp
        ) as prev_time
)
FROM events_with_context
SELECT 
    timestamp,
    username,
    source_ip,
    timestamp - prev_time as time_since_prev_attempt
WHERE success = true 
  AND prev_success = false
  AND timestamp - prev_time < INTERVAL '5 minutes'
ORDER BY timestamp DESC;
```

### Обнаружение сканирования портов

```sql
-- Ищем: IP, который стучится на много разных портов
-- Признак разведки перед атакой
WITH port_scan_candidates AS (
    FROM firewall_logs
    SELECT 
        source_ip,
        destination_ip,
        COUNT(DISTINCT destination_port) as ports_scanned,
        MIN(timestamp) as scan_start,
        MAX(timestamp) as scan_end
    WHERE timestamp > NOW() - INTERVAL '1 hour'
      AND action = 'denied'
    GROUP BY source_ip, destination_ip
    HAVING COUNT(DISTINCT destination_port) > 10
)
FROM port_scan_candidates
SELECT 
    *,
    scan_end - scan_start as scan_duration
ORDER BY ports_scanned DESC;
```

### Построение сессий

```sql
-- Группируем события в сессии (перерыв > 30 мин = новая сессия)
-- Ищем: аномально длинные или короткие сессии
WITH events_with_gaps AS (
    FROM auth_events
    SELECT 
        *,
        CASE 
            WHEN timestamp - LAG(timestamp) OVER (
                PARTITION BY username ORDER BY timestamp
            ) > INTERVAL '30 minutes'
            THEN 1 
            ELSE 0 
        END as is_new_session
),
events_with_sessions AS (
    SELECT 
        *,
        SUM(is_new_session) OVER (
            PARTITION BY username 
            ORDER BY timestamp
        ) as session_id
    FROM events_with_gaps
)
FROM events_with_sessions
SELECT 
    username,
    session_id,
    MIN(timestamp) as session_start,
    MAX(timestamp) as session_end,
    MAX(timestamp) - MIN(timestamp) as session_duration,
    COUNT(*) as events_count
GROUP BY username, session_id
ORDER BY session_duration DESC;
```

### Скользящие агрегаты для обнаружения аномалий

```sql
-- Скользящее среднее: сглаживаем шум, видим тренды
WITH hourly AS (
    FROM auth_events
    SELECT 
        DATE_TRUNC('hour', timestamp) as hour,
        COUNT(*) as events
    GROUP BY ALL
)
FROM hourly
SELECT 
    hour,
    events,
    AVG(events) OVER (
        ORDER BY hour 
        ROWS BETWEEN 2 PRECEDING AND CURRENT ROW
    ) as moving_avg_3h,
    events - AVG(events) OVER (
        ORDER BY hour 
        ROWS BETWEEN 6 PRECEDING AND 1 PRECEDING
    ) as deviation_from_norm
ORDER BY hour;
```

## Занятие 4.3: Корреляция данных и продвинутые кейсы

### Зачем коррелировать данные?

Одиночное событие редко говорит об атаке. Цепочка событий — это история:

__Пример цепочки Lateral Movement:__

1. 09:00 — Неудачные SSH-входы с IP 192.168.1.100 → auth_logs
2. 09:15 — Успешный вход user1 с IP 192.168.1.100 → auth_logs  
3. 09:20 — Исходящее соединение на порт 4444 → firewall_logs
4. 09:21 — DNS-запрос к x7k2m.xyz → dns_logs
5. 09:30 — Вход user1 на сервер с IP 192.168.1.100 → auth_logs (lateral movement!)

### Кейс: Lateral Movement

```sql
-- Ищем: вход с нового хоста (которого не было 30 дней)
-- Признак: злоумышленник перемещается с украденными кредами
WITH 
normal_hosts AS (
    -- Обычные хосты пользователя за последний месяц
    FROM auth_events
    SELECT DISTINCT username, source_ip
    WHERE timestamp BETWEEN NOW() - INTERVAL '30 days' AND NOW() - INTERVAL '1 day'
      AND success = true
),
recent_logins AS (
    -- Входы за последние сутки
    FROM auth_events
    SELECT *
    WHERE timestamp > NOW() - INTERVAL '1 day'
      AND success = true
)
-- Новые хосты = lateral movement кандидаты
FROM recent_logins r
LEFT JOIN normal_hosts n 
    ON r.username = n.username AND r.source_ip = n.source_ip
SELECT 
    r.timestamp,
    r.username,
    r.source_ip as new_host,
    'LATERAL_MOVEMENT_CANDIDATE' as alert_type
WHERE n.source_ip IS NULL
ORDER BY r.timestamp;
```

### Кейс: DGA-домены

```sql
-- Ищем: домены с признаками генерации алгоритмом
-- Высокая энтропия + нетипичная структура
FROM dns_logs
SELECT 
    query_domain,
    source_ip,
    COUNT(*) as query_count,
    LENGTH(SPLIT_PART(query_domain, '.', 1)) as subdomain_length,
    -- Простая эвристика: много цифр в домене
    LENGTH(REGEXP_REPLACE(query_domain, '[^0-9]', '', 'g')) as digit_count
WHERE timestamp > NOW() - INTERVAL '24 hours'
  AND LENGTH(SPLIT_PART(query_domain, '.', 1)) > 10
  AND LENGTH(REGEXP_REPLACE(query_domain, '[^0-9]', '', 'g')) > 2
GROUP BY ALL
HAVING COUNT(*) > 5
ORDER BY query_count DESC;
```

### Кейс: Полная корреляция инцидента

```sql
-- Собираем timeline подозрительной активности с одного IP
WITH 
target_ip AS (SELECT '192.168.1.100'::INET as ip),

auth_timeline AS (
    FROM auth_events, target_ip
    SELECT 
        timestamp,
        'AUTH' as source,
        CASE WHEN success THEN 'login_success' ELSE 'login_failed' END as event,
        username as details
    WHERE source_ip = target_ip.ip
      AND timestamp > NOW() - INTERVAL '24 hours'
),

firewall_timeline AS (
    FROM firewall_logs, target_ip
    SELECT 
        timestamp,
        'FIREWALL' as source,
        action as event,
        destination_ip || ':' || destination_port as details
    WHERE source_ip = target_ip.ip
      AND timestamp > NOW() - INTERVAL '24 hours'
),

dns_timeline AS (
    FROM dns_logs, target_ip
    SELECT 
        timestamp,
        'DNS' as source,
        response_code as event,
        query_domain as details
    WHERE source_ip = target_ip.ip
      AND timestamp > NOW() - INTERVAL '24 hours'
)

-- Объединённый timeline
FROM auth_timeline
UNION ALL SELECT * FROM firewall_timeline
UNION ALL SELECT * FROM dns_timeline
ORDER BY timestamp;
```

## Полезные ресурсы

- [MITRE ATT&CK](https://attack.mitre.org/) — база знаний о тактиках и техниках атак
- [DuckDB SQL Reference](https://duckdb.org/docs/sql/introduction)
- [PostgreSQL Window Functions](https://www.postgresql.org/docs/current/tutorial-window.html)

## Практические задания

### Задание 4.1: Базовая аналитика

Напишите SQL-запросы для анализа таблицы `auth_events`:

1. TOP-10 IP-адресов по количеству неудачных попыток входа за последние 24 часа
2. Распределение событий по часам суток с разбивкой на успешные/неудачные
3. Пользователи с процентом неудачных попыток > 50% (минимум 5 попыток)
4. Часы с аномально высокой активностью (> 2 стандартных отклонений от среднего)

__Чеклист выполнения:__

- [ ] Все 4 запроса выполняются без ошибок
- [ ] Запросы используют агрегации и GROUP BY
- [ ] Результаты отсортированы по релевантности

### Задание 4.2: Оконные функции

Напишите SQL-запросы с использованием оконных функций:

1. Для каждого события добавьте время предыдущего события того же пользователя (LAG)
2. Найдите успешные входы, которым предшествовала неудачная попытка менее 5 минут назад
3. Постройте сессии пользователей (новая сессия, если перерыв > 30 минут)
4. Вычислите скользящее среднее событий за 3 часа

__Чеклист выполнения:__

- [ ] Запросы используют LAG/LEAD, ROW_NUMBER или другие оконные функции
- [ ] Запрос обнаружения brute-force находит подозрительные паттерны
- [ ] Сессии корректно группируют события

### Задание 4.3: Корреляция данных

Напишите сложный аналитический запрос, который:

1. Использует CTE для структурирования логики
2. Соединяет данные из таблицы `auth_events` (минимум 2 подзапроса)
3. Выявляет один из паттернов:
    - Lateral movement (вход с нового хоста)
    - Brute-force с последующим успехом
    - Аномальная активность в нерабочее время

__Чеклист выполнения:__

- [ ] Запрос использует WITH (CTE)
- [ ] Запрос содержит JOIN или коррелированный подзапрос
- [ ] Результат выявляет реальный паттерн атаки
