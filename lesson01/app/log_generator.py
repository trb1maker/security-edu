"""
Генератор событий аутентификации для имитации реальной активности.

Генерирует события:
- login_success: успешный вход
- login_failure: неудачная попытка входа
- logout: выход из системы

Имитирует реалистичные паттерны:
- Нормальная активность в рабочее время
- Периодические brute-force атаки
- Подозрительные входы с необычных IP
"""

import json
import logging
import os
import random
import time
from datetime import datetime

import psycopg2
from psycopg2 import OperationalError

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Конфигурация из переменных окружения
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "security_logs")
DB_USER = os.getenv("DB_USER", "analyst")
DB_PASSWORD = os.getenv("DB_PASSWORD", "security123")

# Параметры генерации
EVENTS_PER_BATCH = int(os.getenv("EVENTS_PER_BATCH", "10"))
BATCH_INTERVAL = int(os.getenv("BATCH_INTERVAL", "5"))  # секунды между батчами
ATTACK_PROBABILITY = float(os.getenv("ATTACK_PROBABILITY", "0.1"))  # вероятность атаки

# Данные для генерации
NORMAL_USERS = ["admin", "analyst", "operator", "user1", "user2", "user3", "developer", "manager"]
ATTACKERS = ["unknown", "hacker", "scanner", "bot"]

INTERNAL_IPS = [
    "192.168.1.100", "192.168.1.101", "192.168.1.102",
    "10.0.0.50", "10.0.0.51", "10.0.0.52",
    "172.16.0.10", "172.16.0.11"
]

EXTERNAL_IPS = [
    "203.0.113.42", "198.51.100.77", "45.33.32.156",
    "91.121.87.10", "185.220.101.1", "23.129.64.100"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0",
    "python-requests/2.28.0"
]

AUTH_METHODS = ["password", "ssh_key", "certificate", "2fa"]


def get_db_connection():
    """Создание подключения к базе данных с повторными попытками."""
    max_retries = 10
    retry_delay = 3
    
    for attempt in range(max_retries):
        try:
            conn = psycopg2.connect(
                host=DB_HOST,
                port=DB_PORT,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD
            )
            logger.info("Успешное подключение к базе данных")
            return conn
        except OperationalError as e:
            logger.warning(f"Попытка {attempt + 1}/{max_retries}: не удалось подключиться к БД: {e}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
            else:
                raise


def ensure_table_exists(conn):
    """Создание таблицы, если она не существует."""
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS auth_events (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        source_ip INET NOT NULL,
        username VARCHAR(255) NOT NULL,
        event_type VARCHAR(50) NOT NULL CHECK (
            event_type IN ('login_success', 'login_failure', 'logout')
        ),
        details JSONB
    );
    
    CREATE INDEX IF NOT EXISTS idx_auth_events_timestamp ON auth_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_auth_events_source_ip ON auth_events(source_ip);
    CREATE INDEX IF NOT EXISTS idx_auth_events_username ON auth_events(username);
    CREATE INDEX IF NOT EXISTS idx_auth_events_event_type ON auth_events(event_type);
    """
    
    with conn.cursor() as cursor:
        cursor.execute(create_table_sql)
    conn.commit()
    logger.info("Таблица auth_events готова")


def generate_normal_event():
    """Генерация нормального события аутентификации."""
    username = random.choice(NORMAL_USERS)
    source_ip = random.choice(INTERNAL_IPS)
    
    # Вероятности для нормальной активности
    event_weights = {
        "login_success": 0.6,
        "logout": 0.3,
        "login_failure": 0.1  # редкие ошибки (опечатки в пароле)
    }
    
    event_type = random.choices(
        list(event_weights.keys()),
        weights=list(event_weights.values())
    )[0]
    
    details = {
        "method": random.choice(AUTH_METHODS),
        "user_agent": random.choice(USER_AGENTS)
    }
    
    if event_type == "login_failure":
        details["reason"] = random.choice(["invalid_password", "expired_password"])
        details["attempt"] = random.randint(1, 2)  # pyright: ignore[reportArgumentType]
    elif event_type == "logout":
        details["session_duration_minutes"] = random.randint(5, 480)  # pyright: ignore[reportArgumentType]
    
    return {
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
        "details": details
    }


def generate_attack_event():
    """Генерация события, похожего на атаку."""
    attack_type = random.choice(["brute_force", "credential_stuffing", "scanning"])
    
    if attack_type == "brute_force":
        # Много попыток с одного IP на одного пользователя
        return {
            "source_ip": random.choice(EXTERNAL_IPS),
            "username": random.choice(NORMAL_USERS + ATTACKERS),
            "event_type": "login_failure",
            "details": {
                "method": "password",
                "reason": random.choice(["invalid_password", "user_not_found", "account_locked"]),
                "attempt": random.randint(5, 50),
                "user_agent": "python-requests/2.28.0"
            }
        }
    elif attack_type == "credential_stuffing":
        # Попытки с разными пользователями
        return {
            "source_ip": random.choice(EXTERNAL_IPS),
            "username": random.choice(ATTACKERS),
            "event_type": "login_failure",
            "details": {
                "method": "password",
                "reason": "user_not_found",
                "user_agent": "curl/7.68.0"
            }
        }
    else:  # scanning
        # Успешный вход после множества неудачных (компрометация)
        return {
            "source_ip": random.choice(EXTERNAL_IPS),
            "username": random.choice(NORMAL_USERS),
            "event_type": random.choice(["login_failure", "login_success"]),
            "details": {
                "method": "ssh_key",
                "user_agent": "OpenSSH_8.2p1",
                "suspicious": True
            }
        }


def generate_events(count: int) -> list:
    """Генерация батча событий."""
    events = []
    
    for _ in range(count):
        if random.random() < ATTACK_PROBABILITY:
            event = generate_attack_event()
        else:
            event = generate_normal_event()
        events.append(event)
    
    return events


def insert_events(conn, events: list):
    """Вставка событий в базу данных."""
    insert_sql = """
    INSERT INTO auth_events (source_ip, username, event_type, details)
    VALUES (%s, %s, %s, %s)
    """
    
    with conn.cursor() as cursor:
        for event in events:
            cursor.execute(insert_sql, (
                event["source_ip"],
                event["username"],
                event["event_type"],
                json.dumps(event["details"])
            ))
    conn.commit()


def main():
    """Основной цикл генерации событий."""
    logger.info("Запуск генератора событий аутентификации")
    logger.info(f"Параметры: {EVENTS_PER_BATCH} событий каждые {BATCH_INTERVAL} сек, "
                f"вероятность атаки: {ATTACK_PROBABILITY}")
    
    conn = get_db_connection()
    ensure_table_exists(conn)
    
    total_events = 0
    
    try:
        while True:
            events = generate_events(EVENTS_PER_BATCH)
            insert_events(conn, events)
            total_events += len(events)
            
            logger.info(f"Сгенерировано {len(events)} событий (всего: {total_events})")
            
            time.sleep(BATCH_INTERVAL)
            
    except KeyboardInterrupt:
        logger.info("Остановка генератора")
    finally:
        conn.close()  # pyright: ignore[reportOptionalMemberAccess]
        logger.info(f"Завершено. Всего сгенерировано событий: {total_events}")


if __name__ == "__main__":
    main()
