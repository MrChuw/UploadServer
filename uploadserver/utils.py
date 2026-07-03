from __future__ import annotations

import asyncio
import hashlib
import io
import os
import re
import secrets
import string
from contextlib import suppress
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated

import mutagen
import umami
from dotenv import load_dotenv
from fastapi import Header, HTTPException, UploadFile
from mutagen.id3 import ID3
from mutagen.mp4 import MP4
from PIL import Image, ImageOps
from starlette import status
from tortoise import timezone
from tortoise.transactions import in_transaction

from uploadserver.models import APIKey, DeletedFileLog, Tag, UploadedFile, UserRole

load_dotenv()


FORWARDED_PROTO = os.getenv("FORWARDED_PROTO", None)

BASE_DIR = Path(__file__).resolve().parent

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR.parent}/db/db.sqlite3")
UPLOAD_DIR_STR = os.getenv("UPLOAD_DIR", "../uploads")
TRASH_DIR_STR = os.getenv("TRASH_DIR", "../uploads/.trash")

UPLOAD_DIR = (BASE_DIR / UPLOAD_DIR_STR).resolve()
TRASH_DIR = (BASE_DIR / TRASH_DIR_STR).resolve()

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
TRASH_DIR.mkdir(parents=True, exist_ok=True)

if DATABASE_URL.startswith("sqlite:///"):
    sqlite_path_str = DATABASE_URL.replace("sqlite:///", "")
    sqlite_file_path = Path(sqlite_path_str).resolve()
    sqlite_file_path.parent.mkdir(parents=True, exist_ok=True)

MAX_NAME_LENGTH = int(os.getenv("MAX_NAME_LENGTH", 64))

try:
    DEFAULT_MAX_UPLOAD_SIZE = int(os.getenv("DEFAULT_MAX_UPLOAD_SIZE", 100 * 1024 * 1024))
except ValueError:
    DEFAULT_MAX_UPLOAD_SIZE = 100 * 1024 * 1024

try:
    INITIAL_TOKEN_LENGTH = int(os.getenv("INITIAL_TOKEN_LENGTH", 5))
except ValueError:
    INITIAL_TOKEN_LENGTH = 5

RESERVED_NAMES_RAW = os.getenv("RESERVED_NAMES")
if RESERVED_NAMES_RAW:
    RESERVED_NAMES = {name.strip().lower() for name in RESERVED_NAMES_RAW.split(",") if name.strip()}
else:
    RESERVED_NAMES = {"api", "static", "assets"}

UMAMI_URL_BASE = os.getenv("UMAMI_URL_BASE", None)
UMAMI_WEBSITE_ID = os.getenv("UMAMI_WEBSITE_ID", None)
UMAMI_HOSTNAME = os.getenv("UMAMI_HOSTNAME", None)


async def cron_ttl_and_trash_purger() -> None:
    while True:
        try:
            now = timezone.now()
            expired_files = await UploadedFile.filter(expires_at__lte=now)
            for file_record in expired_files:
                await execute_file_deletion(file_record)

            purgable_logs = await DeletedFileLog.filter(purge_at__lte=now)
            for log in purgable_logs:
                if log.trash_path:
                    trash_file = Path(log.trash_path)
                    if trash_file.exists():
                        with suppress(OSError):
                            trash_file.unlink()
                await log.delete()
        except Exception as cleaner_error:
            print(f"[Background Task Error]: {cleaner_error}")

        await asyncio.sleep(60)


async def get_or_create_tags(tag_names: list[str]) -> list[Tag]:
    tags = []
    for name in tag_names:
        cleaned = re.sub(r"[^a-zA-Z0-9_\-]", "", name.strip().lower())
        if cleaned:
            tag, _ = await Tag.get_or_create(name=cleaned)
            tags.append(tag)
    return tags


async def execute_file_deletion(file_record: UploadedFile) -> None:
    async with in_transaction():
        source_path = Path(file_record.saved_path).resolve()
        purge_time = timezone.now() + timedelta(hours=1)

        is_shared_link = (
            await UploadedFile.filter(saved_path=file_record.saved_path).exclude(id=file_record.id).exists()
        )

        target_trash_path = ""
        if source_path.exists():
            if not is_shared_link:
                trash_filename = f"{secrets.token_hex(8)}_{source_path.name}"
                target_trash_path = TRASH_DIR / trash_filename
                os.rename(source_path, target_trash_path)
            else:
                source_path.unlink()

        await DeletedFileLog.create(
            original_id=file_record.id,
            filename=file_record.filename,
            file_size=file_record.file_size,
            file_hash=file_record.file_hash,
            uploaded_at=file_record.uploaded_at,
            purge_at=purge_time,
            trash_path=str(target_trash_path) if target_trash_path else "",
            meta_json={"ip_address": file_record.ip_address, "country": file_record.country},
        )
        await file_record.delete()


async def purge_trash_on_startup() -> None:
    try:
        now = timezone.now()
        print("[Startup Trash Purger] Checking trash directory...")

        # 1. Clear files that have been in the trash for over an hour (expired)
        expired_logs = await DeletedFileLog.filter(purge_at__lte=now)
        count_purged = 0

        for log in expired_logs:
            if log.trash_path:
                trash_file = Path(log.trash_path)
                if trash_file.exists():
                    with suppress(OSError):
                        trash_file.unlink()
            await log.delete()
            count_purged += 1

        if count_purged > 0:
            print(f"[Startup Trash Purger] Successfully purged {count_purged} expired file(s) from .trash.")
        else:
            print("[Startup Trash Purger] No expired files found in trash.")

        pending_count = await DeletedFileLog.filter(purge_at__gt=now).count()
        if pending_count > 0:
            print(
                f"[Startup Trash Purger] {pending_count} file(s) have been in trash for less than 1h and "
                f"will be handled by the background cron."
            )

    except Exception as startup_error:
        print(f"[Startup Trash Purger Error]: {startup_error}")


def generate_secure_token(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def verify_api_key(
    x_api_key: Annotated[str | None, Header(include_in_schema=False)] = None,
) -> APIKey:
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-API-Key header.")
    key_record = await APIKey.filter(key=x_api_key).first()
    if not key_record:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or revoked API Key.")
    return key_record


class CloudflareMetadata:
    def __init__(
        self,
        cf_connecting_ip: Annotated[str | None, Header(include_in_schema=False)] = None,
        cf_ipcountry: Annotated[str | None, Header(include_in_schema=False)] = None,
        x_forwarded_for: Annotated[str | None, Header(include_in_schema=False)] = None,
        user_agent: Annotated[str | None, Header(alias="User-Agent", include_in_schema=False)] = "Unknown",
    ):
        self.ip = cf_connecting_ip or (x_forwarded_for.split(",")[0].strip() if x_forwarded_for else "127.0.0.1")
        self.country = cf_ipcountry or "XX"
        self.ua = user_agent


def _strip_all_metadata(contents: bytes, extension: str) -> bytes:
    if extension in {
        ".jpg",
        ".jpeg",
        ".tif",
        ".tiff",
        ".png",
        ".webp",
        ".heic",
        ".heif",
        ".avif",
    }:
        try:
            image = Image.open(io.BytesIO(contents))
            with suppress(Exception):
                image = ImageOps.exif_transpose(image)

            output_buffer = io.BytesIO()
            save_format = (
                image.format if image.format else ("JPEG" if extension in {".jpg", ".jpeg"} else extension[1:].upper())
            )
            image.save(output_buffer, format=save_format, optimize=True)
            return output_buffer.getvalue()
        except Exception as e:
            print(f"[Metadata Stripper] Failed cleaning image: {e}")
            return contents

    elif extension in {".mp4", ".m4v", ".mov", ".mp3"}:
        if mutagen is None:
            print("[Metadata Stripper Warning] Mutagen library missing. Skipping media scrub.")
            return contents
        try:
            file_stream = io.BytesIO(contents)

            if extension in {".mp4", ".m4v", ".mov"}:
                video = MP4(file_stream)
                video.delete()
                video.save(file_stream)
            elif extension == ".mp3":
                audio = ID3(file_stream)
                audio.delete()
                audio.save(file_stream)

            return file_stream.getvalue()
        except Exception as e:
            print(f"[Metadata Stripper] Failed scrubbing media tags for {extension}: {e}")
            return contents

    return contents


async def process_and_save_upload(
    file: UploadFile,
    subfolder: str,
    provided_tags: list[str],
    ttl_seconds: int | None,
    api_key_record: APIKey,
    network: CloudflareMetadata,
    base_url: str,
    clean_metadata: bool = False,
) -> dict[str, str]:
    max_allowed_size = api_key_record.max_upload_size or DEFAULT_MAX_UPLOAD_SIZE
    if api_key_record.role == UserRole.VIP:
        max_allowed_size *= 2
    elif api_key_record.role == UserRole.OWNER:
        max_allowed_size = 10 * 1024 * 1024 * 1024

    file.file.seek(0, os.SEEK_END)
    file_size = file.file.tell()
    file.file.seek(0)

    if file_size > max_allowed_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File size exceeds operational limit constraints.",
        )

    target_dir = (UPLOAD_DIR / subfolder if subfolder else UPLOAD_DIR).resolve()
    if UPLOAD_DIR not in target_dir.parents and target_dir != UPLOAD_DIR:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Directory traversal attempt blocked.")

    if api_key_record.role == UserRole.OWNER:
        provided_tags.append("owner")
    elif api_key_record.role == UserRole.VIP:
        provided_tags.append("vip")
    elif api_key_record.role == UserRole.NORMAL:
        provided_tags.append("normal")

    if api_key_record.owner:
        provided_tags.append(api_key_record.owner)

    db_tags = await get_or_create_tags(provided_tags)
    expiration_date = timezone.now() + timedelta(seconds=ttl_seconds) if ttl_seconds else None

    contents = await file.read()
    original_path = Path(file.filename or "file.bin")
    extension = original_path.suffix.lower()

    if clean_metadata:
        contents = _strip_all_metadata(contents, extension)
        file_size = len(contents)

    sha256_hash = hashlib.sha256()
    sha256_hash.update(contents)
    computed_hash = sha256_hash.hexdigest()

    deletion_token = secrets.token_urlsafe(48)
    existing_file = await UploadedFile.filter(file_hash=computed_hash).first()

    if UMAMI_URL_BASE and UMAMI_WEBSITE_ID and UMAMI_HOSTNAME:
        asyncio.create_task(  # noqa: RUF006
            umami.new_event_async(
                event_name="file_upload",
                hostname=UMAMI_HOSTNAME,
                url="/api/upload",
                website_id=UMAMI_WEBSITE_ID,
                title="File Upload Event",
                custom_data={
                    "size": file_size,
                    "owner": api_key_record.owner,
                    "scope": subfolder or "root",
                    "tags": provided_tags,
                },
                ip_address=network.ip,
            )
        )

    current_token_length = INITIAL_TOKEN_LENGTH
    target_dir.mkdir(parents=True, exist_ok=True)

    while True:
        random_string = generate_secure_token(current_token_length)
        target_filename = f"{random_string}{extension}"
        final_path = (target_dir / target_filename).resolve()
        relative_url_path = f"{subfolder}/{target_filename}" if subfolder else target_filename
        if not final_path.exists():
            break
        current_token_length += 1

    base_url_clean = base_url.rstrip("/")

    full_file_url = f"{base_url_clean}/{relative_url_path.lstrip('/')}"
    full_deletion_url = f"{base_url_clean}/api/delete/{deletion_token}"

    if existing_file:
        existing_real_path = Path(existing_file.saved_path).resolve()

        if existing_real_path.exists():
            try:
                os.link(existing_real_path, final_path)
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Hard link operation mismatch."
                ) from e

            new_record = await UploadedFile.create(
                filename=file.filename,
                saved_path=str(final_path),
                file_size=file_size,
                file_hash=computed_hash,
                expires_at=expiration_date,
                ip_address=network.ip,
                country=network.country,
                deletion_token=deletion_token,
                api_key=api_key_record,
            )
            await new_record.tags.add(*db_tags)

            return {
                "status": "success",
                "url": full_file_url,
                "thumbnail_url": full_file_url,
                "deletion_url": full_deletion_url,
                "hash": computed_hash,
                "deduplicated": "true",
                "error": "",
            }

    try:
        with open(final_path, "wb") as buffer:
            buffer.write(contents)
    except Exception as e:
        if final_path.exists():
            final_path.unlink()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Disk resources failed: {e!s}"
        ) from e

    new_record = await UploadedFile.create(
        filename=file.filename,
        saved_path=str(final_path),
        file_size=file_size,
        file_hash=computed_hash,
        expires_at=expiration_date,
        ip_address=network.ip,
        country=network.country,
        deletion_token=deletion_token,
        api_key=api_key_record,
    )
    await new_record.tags.add(*db_tags)

    return {
        "status": "success",
        "url": full_file_url,
        "thumbnail_url": full_file_url,
        "deletion_url": full_deletion_url,
        "hash": computed_hash,
        "deduplicated": "false",
        "error": "",
    }


def sanitize_subfolder_name(name: str | None) -> str:
    if not name:
        return ""
    if len(name) > MAX_NAME_LENGTH:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scope parameter execution size overflow.")
    cleaned_name = re.sub(r"[^a-zA-Z0-9_\-]", "", name.strip().lower())
    if not cleaned_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scope target configuration.")
    if cleaned_name in RESERVED_NAMES:
        cleaned_name = f"_{cleaned_name}"
    return cleaned_name


def parse_time_range(from_date: str | None, to_date: str | None, days: int | None):
    filters = {}
    if days is not None:
        start_bound = timezone.now() - timedelta(days=days)
        filters["uploaded_at__gte"] = start_bound
    else:
        if from_date:
            filters["uploaded_at__gte"] = datetime.strptime(from_date, "%Y-%m-%d")
        if to_date:
            filters["uploaded_at__lte"] = datetime.strptime(to_date, "%Y-%m-%d")
    return filters
