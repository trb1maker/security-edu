"""
Скрипт загрузки предварительно сгенерированных данных из S3.

Поддерживает две версии датасета:
- lite: данные за 14 дней атаки (~500 MB)
- full: полный набор данных за 81 день (~2.1 GB)
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv
from tqdm import tqdm

PROJECT_ROOT = Path(__file__).resolve().parent

env_path = PROJECT_ROOT / ".env"
if env_path.exists():
    load_dotenv(env_path)
else:
    load_dotenv()  # Попробуем загрузить из текущей директории

S3_BUCKET = os.getenv("S3_BUCKET", "security-edu-data")
S3_ENDPOINT_URL = os.getenv("S3_ENDPOINT_URL", None)  # Для Yandex Cloud или MinIO
S3_REGION = os.getenv("S3_REGION", "ru-central1")

DATA_DIR = PROJECT_ROOT / "data"


def get_s3_client():
    """Создать клиент S3 с credentials из переменных окружения."""
    aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")

    if not aws_access_key_id or not aws_secret_access_key:
        raise ValueError(
            "Необходимо установить AWS_ACCESS_KEY_ID и AWS_SECRET_ACCESS_KEY "
            "в переменных окружения или файле .env"
        )

    config = {
        "aws_access_key_id": aws_access_key_id,
        "aws_secret_access_key": aws_secret_access_key,
        "region_name": S3_REGION,
    }

    if S3_ENDPOINT_URL:
        config["endpoint_url"] = S3_ENDPOINT_URL

    return boto3.client("s3", **config)


def download_file(
    s3_client, bucket: str, key: str, local_path: Path, expected_size: int | None = None
):
    """Скачать файл из S3 с прогресс-баром."""
    local_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Получить размер файла для прогресс-бара
        if expected_size is None:
            response = s3_client.head_object(Bucket=bucket, Key=key)
            expected_size = response["ContentLength"]

        # Скачать файл
        with tqdm(
            total=expected_size, unit="B", unit_scale=True, desc=local_path.name
        ) as pbar:

            def callback(bytes_amount):
                pbar.update(bytes_amount)

            s3_client.download_file(bucket, key, str(local_path), Callback=callback)

        return True

    except ClientError as e:
        print(f"Ошибка при скачивании {key}: {e}", file=sys.stderr)
        return False


def verify_file_checksum(file_path: Path, expected_checksum: str) -> bool:
    """Проверить checksum файла."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)

    actual_checksum = sha256.hexdigest()
    return actual_checksum == expected_checksum


def load_manifest(s3_client, bucket: str, version: str) -> dict | None:
    """Загрузить manifest.json для версии датасета."""
    manifest_key = f"{version}/manifest.json"

    try:
        response = s3_client.get_object(Bucket=bucket, Key=manifest_key)
        manifest_data = json.loads(response["Body"].read().decode("utf-8"))
        return manifest_data
    except ClientError as e:
        print(f"Ошибка при загрузке manifest: {e}", file=sys.stderr)
        return None


def download_dataset(version: str, verify: bool = True):
    """Скачать датасет указанной версии."""
    print(f"Загрузка датасета версии '{version}'...")

    try:
        s3_client = get_s3_client()
    except ValueError as e:
        print(f"Ошибка конфигурации: {e}", file=sys.stderr)
        sys.exit(1)
    except NoCredentialsError:
        print("Ошибка: не найдены credentials для S3", file=sys.stderr)
        sys.exit(1)

    # Загрузить manifest
    manifest = load_manifest(s3_client, S3_BUCKET, version)
    if not manifest:
        print(f"Не удалось загрузить manifest для версии '{version}'", file=sys.stderr)
        sys.exit(1)

    print(f"Версия: {manifest.get('version', version)}")
    print(f"Дата генерации: {manifest.get('generated_at', 'неизвестно')}")
    print(f"Файлов: {len(manifest.get('files', []))}")

    # Создать директорию для версии
    version_dir = DATA_DIR / version
    version_dir.mkdir(parents=True, exist_ok=True)

    # Скачать все файлы из manifest
    files = manifest.get("files", [])
    failed_files = []

    for file_info in files:
        file_name = file_info["name"]
        s3_key = f"{version}/{file_name}"
        local_path = version_dir / file_name
        expected_size = file_info.get("size")
        expected_checksum = file_info.get("sha256")

        # Проверить, не скачан ли уже файл
        if local_path.exists() and expected_checksum:
            if verify_file_checksum(local_path, expected_checksum):
                print(f"✓ {file_name} уже скачан и проверен")
                continue

        # Скачать файл
        print(f"\nСкачивание {file_name}...")
        if download_file(s3_client, S3_BUCKET, s3_key, local_path, expected_size):
            # Проверить checksum
            if expected_checksum and verify:
                if verify_file_checksum(local_path, expected_checksum):
                    print(f"✓ {file_name} скачан и проверен")
                else:
                    print(
                        f"✗ Ошибка проверки checksum для {file_name}", file=sys.stderr
                    )
                    failed_files.append(file_name)
                    local_path.unlink()  # Удалить поврежденный файл
            else:
                print(f"✓ {file_name} скачан")
        else:
            failed_files.append(file_name)

    # Сохранить manifest локально
    manifest_path = version_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    # Итоги
    print(f"\n{'=' * 60}")
    if failed_files:
        print(f"Ошибка: не удалось скачать {len(failed_files)} файлов:")
        for f in failed_files:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print(f"✓ Все файлы успешно скачаны в {version_dir}")
        print(f"✓ Manifest сохранен в {manifest_path}")


def main():
    """Главная функция."""
    parser = argparse.ArgumentParser(
        description="Загрузка предварительно сгенерированных данных из S3"
    )
    parser.add_argument(
        "--version",
        choices=["lite", "full"],
        default="lite",
        help="Версия датасета для загрузки (по умолчанию: lite)",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Не проверять checksum файлов",
    )

    args = parser.parse_args()

    download_dataset(args.version, verify=not args.no_verify)


if __name__ == "__main__":
    main()
