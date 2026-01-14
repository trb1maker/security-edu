-- Миграция 001: Адаптация схемы и создание оптимизированных индексов
-- 
-- Эта миграция:
-- 1. Добавляет колонку severity, если её нет (для данных из Блока 1)
-- 2. Заполняет severity на основе существующих данных
-- 3. Создаёт оптимизированные индексы для аналитических запросов
--
-- Эти индексы ускоряют типичные запросы поиска индикаторов атаки:
-- - Поиск по IP-адресам и временным диапазонам
-- - Агрегации по типам событий и severity
-- - Поиск паттернов brute-force и подозрительной активности

-- ============================================================================
-- АДАПТАЦИЯ СХЕМЫ: Добавление колонки severity
-- ============================================================================

-- AUTH_EVENTS: Добавляем severity, если её нет
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'auth_events' AND column_name = 'severity'
    ) THEN
        ALTER TABLE auth_events ADD COLUMN severity VARCHAR(10);
        
        -- Заполняем severity на основе event_type и success
        UPDATE auth_events 
        SET severity = CASE 
            WHEN event_type = 'login_failure' AND success = false THEN 'warning'
            WHEN event_type = 'login_success' AND success = true THEN 'info'
            WHEN event_type = 'logout' THEN 'info'
            ELSE 'info'
        END;
        
        -- Делаем колонку NOT NULL после заполнения
        ALTER TABLE auth_events ALTER COLUMN severity SET NOT NULL;
        ALTER TABLE auth_events ALTER COLUMN severity SET DEFAULT 'info';
    END IF;
END $$;

-- NGINX_LOGS: Добавляем severity, если её нет
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'nginx_logs' AND column_name = 'severity'
    ) THEN
        ALTER TABLE nginx_logs ADD COLUMN severity VARCHAR(10);
        
        -- Заполняем severity на основе status
        UPDATE nginx_logs 
        SET severity = CASE 
            WHEN status >= 500 THEN 'error'
            WHEN status >= 400 THEN 'warning'
            ELSE 'info'
        END;
        
        ALTER TABLE nginx_logs ALTER COLUMN severity SET NOT NULL;
        ALTER TABLE nginx_logs ALTER COLUMN severity SET DEFAULT 'info';
    END IF;
END $$;

-- DNS_QUERIES: Добавляем severity, если её нет
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'dns_queries' AND column_name = 'severity'
    ) THEN
        ALTER TABLE dns_queries ADD COLUMN severity VARCHAR(10);
        
        -- Для DNS по умолчанию info (можно улучшить логику позже)
        UPDATE dns_queries SET severity = 'info';
        
        ALTER TABLE dns_queries ALTER COLUMN severity SET NOT NULL;
        ALTER TABLE dns_queries ALTER COLUMN severity SET DEFAULT 'info';
    END IF;
END $$;

-- FIREWALL_EVENTS: Добавляем severity, если её нет
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'firewall_events' AND column_name = 'severity'
    ) THEN
        ALTER TABLE firewall_events ADD COLUMN severity VARCHAR(10);
        
        -- Заполняем severity на основе action и reason
        UPDATE firewall_events 
        SET severity = CASE 
            WHEN action = 'BLOCK' AND reason LIKE '%port_scan%' THEN 'error'
            WHEN action = 'BLOCK' AND reason LIKE '%brute_force%' THEN 'error'
            WHEN action = 'BLOCK' THEN 'warning'
            ELSE 'info'
        END;
        
        ALTER TABLE firewall_events ALTER COLUMN severity SET NOT NULL;
        ALTER TABLE firewall_events ALTER COLUMN severity SET DEFAULT 'info';
    END IF;
END $$;

-- ============================================================================
-- СОЗДАНИЕ ИНДЕКСОВ
-- ============================================================================

-- ============================================================================
-- AUTH_EVENTS: Индексы для поиска атак на аутентификацию
-- ============================================================================

-- Композитный индекс для поиска неудачных попыток входа по IP и времени
-- Используется для обнаружения brute-force атак
CREATE INDEX IF NOT EXISTS idx_auth_events_ip_time_failures 
ON auth_events(source_ip, timestamp) 
WHERE event_type = 'login_failure';

-- Индекс для поиска успешных входов после неудачных попыток
-- Используется для обнаружения компрометации аккаунтов
CREATE INDEX IF NOT EXISTS idx_auth_events_username_time 
ON auth_events(username, timestamp) 
WHERE success = true;

-- Индекс для агрегации по типам событий и severity
CREATE INDEX IF NOT EXISTS idx_auth_events_type_severity 
ON auth_events(event_type, severity, timestamp);

-- Частичный индекс для подозрительных событий (только warning и error)
-- Уменьшает размер индекса и ускоряет поиск проблемных событий
CREATE INDEX IF NOT EXISTS idx_auth_events_suspicious 
ON auth_events(timestamp, source_ip) 
WHERE severity IN ('warning', 'error');

-- ============================================================================
-- NGINX_LOGS: Индексы для поиска атак на веб-сервер
-- ============================================================================

-- Композитный индекс для поиска ошибок по IP и времени
-- Используется для обнаружения сканирования и атак на веб-приложение
CREATE INDEX IF NOT EXISTS idx_nginx_logs_ip_time_errors 
ON nginx_logs(source_ip, timestamp) 
WHERE status >= 400;

-- Индекс для поиска подозрительных путей (admin, api, login и т.д.)
CREATE INDEX IF NOT EXISTS idx_nginx_logs_path_time 
ON nginx_logs(path, timestamp) 
WHERE path LIKE '/admin%' OR path LIKE '/api/%' OR path LIKE '/login%';

-- Индекс для агрегации по статусам и severity
CREATE INDEX IF NOT EXISTS idx_nginx_logs_status_severity 
ON nginx_logs(status, severity, timestamp);

-- Частичный индекс для блокированных запросов
CREATE INDEX IF NOT EXISTS idx_nginx_logs_blocked 
ON nginx_logs(timestamp, source_ip, path) 
WHERE severity = 'error';

-- ============================================================================
-- DNS_QUERIES: Индексы для поиска подозрительных DNS-запросов
-- ============================================================================

-- Композитный индекс для поиска запросов по домену и времени
-- Используется для обнаружения DGA-доменов и C2-каналов
CREATE INDEX IF NOT EXISTS idx_dns_queries_domain_time 
ON dns_queries(query_domain, timestamp);

-- Индекс для поиска запросов от подозрительных IP
CREATE INDEX IF NOT EXISTS idx_dns_queries_ip_time 
ON dns_queries(source_ip, timestamp);

-- Индекс для поиска запросов к внешним резолверам (8.8.8.8 и т.д.)
-- Может указывать на обход корпоративного DNS
CREATE INDEX IF NOT EXISTS idx_dns_queries_resolver_time 
ON dns_queries(resolver, timestamp) 
WHERE resolver IS NOT NULL;

-- ============================================================================
-- FIREWALL_EVENTS: Индексы для поиска сетевых атак
-- ============================================================================

-- Композитный индекс для поиска блокированных соединений
-- Используется для обнаружения сканирования портов и атак
CREATE INDEX IF NOT EXISTS idx_firewall_events_blocked 
ON firewall_events(source_ip, dest_port, timestamp) 
WHERE action = 'BLOCK';

-- Индекс для поиска подозрительных портов (22, 3389, 5432 и т.д.)
CREATE INDEX IF NOT EXISTS idx_firewall_events_suspicious_ports 
ON firewall_events(dest_port, timestamp, source_ip) 
WHERE dest_port IN (22, 23, 3389, 5432, 3306, 6379);

-- Индекс для поиска сканирования портов (много попыток к разным портам)
CREATE INDEX IF NOT EXISTS idx_firewall_events_port_scan 
ON firewall_events(source_ip, timestamp, dest_port) 
WHERE reason LIKE '%port_scan%' OR reason LIKE '%scan%';

-- Индекс для агрегации по протоколам и действиям
CREATE INDEX IF NOT EXISTS idx_firewall_events_protocol_action 
ON firewall_events(protocol, action, severity, timestamp);

-- ============================================================================
-- Универсальные индексы для временных диапазонов
-- ============================================================================

-- BRIN индексы для временных меток (эффективны для больших таблиц)
-- BRIN занимает меньше места и хорошо работает для временных рядов
CREATE INDEX IF NOT EXISTS idx_auth_events_timestamp_brin 
ON auth_events USING BRIN(timestamp);

CREATE INDEX IF NOT EXISTS idx_nginx_logs_timestamp_brin 
ON nginx_logs USING BRIN(timestamp);

CREATE INDEX IF NOT EXISTS idx_dns_queries_timestamp_brin 
ON dns_queries USING BRIN(timestamp);

CREATE INDEX IF NOT EXISTS idx_firewall_events_timestamp_brin 
ON firewall_events USING BRIN(timestamp);

-- ============================================================================
-- Комментарии к индексам
-- ============================================================================

COMMENT ON INDEX idx_auth_events_ip_time_failures IS 
'Ускоряет поиск неудачных попыток входа по IP для обнаружения brute-force атак';

COMMENT ON INDEX idx_auth_events_username_time IS 
'Ускоряет поиск успешных входов пользователя для обнаружения компрометации';

COMMENT ON INDEX idx_nginx_logs_ip_time_errors IS 
'Ускоряет поиск ошибок веб-сервера по IP для обнаружения атак';

COMMENT ON INDEX idx_firewall_events_blocked IS 
'Ускоряет поиск блокированных соединений для обнаружения сканирования портов';

-- ============================================================================
-- Обновление статистики для оптимизатора
-- ============================================================================

-- После создания индексов необходимо обновить статистику,
-- чтобы PostgreSQL мог принимать правильные решения о выборе плана выполнения
ANALYZE auth_events;
ANALYZE nginx_logs;
ANALYZE dns_queries;
ANALYZE firewall_events;
