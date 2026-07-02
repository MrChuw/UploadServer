import asyncio
import secrets
import shutil
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Annotated, Any

import umami
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import FileResponse, HTMLResponse, Response
from tortoise import Tortoise, timezone
from tortoise.contrib.fastapi import register_tortoise
from tortoise.functions import Avg, Count, Max, Min, Sum

from uploadserver.models import APIKey, DeletedFileLog, UploadedFile, UserRole
from uploadserver.utils import (
    DATABASE_URL,
    UMAMI_HOSTNAME,
    UMAMI_URL_BASE,
    UMAMI_WEBSITE_ID,
    UPLOAD_DIR,
    CloudflareMetadata,
    cron_ttl_and_trash_purger,
    execute_file_deletion,
    parse_time_range,
    process_and_save_upload,
    purge_trash_on_startup,
    sanitize_subfolder_name,
    verify_api_key,
)

START_TIME = time.time()

if UMAMI_URL_BASE and UMAMI_WEBSITE_ID and UMAMI_HOSTNAME:
    umami.set_url_base(UMAMI_URL_BASE)
    umami.set_website_id(UMAMI_WEBSITE_ID)
    umami.set_hostname(UMAMI_HOSTNAME)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    await purge_trash_on_startup()
    asyncio.create_task(cron_ttl_and_trash_purger())  # noqa: RUF006
    yield
    await Tortoise.close_connections()


app = FastAPI(title="File Server API", docs_url="/api/docs", redoc_url="/api/redoc", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def serve_root_todo(network: CloudflareMetadata = Depends()) -> str:  # noqa: B008
    if UMAMI_URL_BASE and UMAMI_WEBSITE_ID and UMAMI_HOSTNAME:
        asyncio.create_task(  # noqa: RUF006
            umami.new_page_view_async(
                page_title="Todo Root",
                url="/",
                hostname=UMAMI_HOSTNAME,
                website_id=UMAMI_WEBSITE_ID,
                ua=str(network.ua),
                ip_address=network.ip,
            )
        )
    return "<html><body><h1>TODO</h1></body></html>"


@app.post("/api/upload")
async def upload_file(
    file: UploadFile,
    request: Request,
    name: Annotated[str | None, Header(include_in_schema=False)] = None,
    tags: Annotated[list[str] | None, Query()] = None,
    ttl_seconds: Annotated[int | None, Query()] = None,
    api_key_record: APIKey = Depends(verify_api_key),  # noqa: B008
    network: CloudflareMetadata = Depends(),  # noqa: B008
) -> dict[str, str]:  # noqa: B008
    subfolder = sanitize_subfolder_name(name)
    provided_tags = tags or []
    forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    base_url_string = f"{forwarded_proto}://{request.url.netloc}/"
    return await process_and_save_upload(
        file=file,
        subfolder=subfolder,
        provided_tags=provided_tags,
        ttl_seconds=ttl_seconds,
        api_key_record=api_key_record,
        network=network,
        base_url=base_url_string,
        clean_metadata=True,
    )


@app.post("/api/uploaddoxx")
async def upload_file_doxx(
    file: UploadFile,
    request: Request,
    name: Annotated[str | None, Header(include_in_schema=False)] = None,
    tags: Annotated[list[str] | None, Query()] = None,
    ttl_seconds: Annotated[int | None, Query()] = None,
    api_key_record: APIKey = Depends(verify_api_key),  # noqa: B008
    network: CloudflareMetadata = Depends(),  # noqa: B008
) -> dict[str, str]:
    subfolder = sanitize_subfolder_name(name)
    provided_tags = tags or []

    forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    base_url_string = f"{forwarded_proto}://{request.url.netloc}/"

    return await process_and_save_upload(
        file=file,
        subfolder=subfolder,
        provided_tags=provided_tags,
        ttl_seconds=ttl_seconds,
        api_key_record=api_key_record,
        network=network,
        base_url=base_url_string,
        clean_metadata=False,
    )


@app.get("/api/delete/{token}")
async def delete_file_via_token(token: str, network: CloudflareMetadata = Depends()) -> dict[str, str]:  # noqa: B008
    if len(token) != 64:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed payload token validation.")
    file_record = await UploadedFile.filter(deletion_token=token).prefetch_related("api_key").first()
    if not file_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target record not found or expired.")

    if UMAMI_URL_BASE and UMAMI_WEBSITE_ID and UMAMI_HOSTNAME:
        asyncio.create_task(  # noqa: RUF006
            umami.new_event_async(
                event_name="file_deletion",
                hostname=UMAMI_HOSTNAME,
                url=f"/api/delete/{token}",
                website_id=UMAMI_WEBSITE_ID,
                title="File Deletion Event",
                custom_data={
                    "filename": file_record.filename,
                    "owner": file_record.api_key.owner,
                    "uploaded_at": file_record.uploaded_at.isoformat()
                    if hasattr(file_record.uploaded_at, "isoformat")
                    else str(file_record.uploaded_at),
                },
                ip_address=network.ip,
            )
        )

    await execute_file_deletion(file_record)
    return {"status": "success"}


@app.post("/api/keys")
async def provision_key_via_api(
    owner: str,
    role: UserRole,
    max_size_mb: float | None = None,
    current_user: APIKey = Depends(verify_api_key),  # noqa: B008
    network: CloudflareMetadata = Depends(),  # noqa: B008
) -> dict[str, str]:
    if current_user.role != UserRole.OWNER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Privileged administrative action required.")

    if UMAMI_URL_BASE and UMAMI_WEBSITE_ID and UMAMI_HOSTNAME:
        asyncio.create_task(  # noqa: RUF006
            umami.new_event_async(
                event_name="key_provision",
                hostname=UMAMI_HOSTNAME,
                url="/api/keys",
                website_id=UMAMI_WEBSITE_ID,
                title="Key Provisioning Event",
                custom_data={"new_owner": owner, "new_role": role.value, "created_by": current_user.owner},
                ip_address=network.ip,
            )
        )

    generated_key = f"sk_{secrets.token_hex(24)}"
    max_size_bytes = int(max_size_mb * 1024 * 1024) if max_size_mb is not None else None
    new_key = await APIKey.create(key=generated_key, owner=owner, role=role, max_upload_size=max_size_bytes)
    return {"owner": new_key.owner, "key": new_key.key, "role": new_key.role.value}


@app.get("/api/metrics/user")
async def get_user_metrics(
    from_date: Annotated[str | None, Query(alias="from")] = None,
    to_date: Annotated[str | None, Query(alias="to")] = None,
    days: Annotated[int | None, Query()] = None,
    current_user: APIKey = Depends(verify_api_key),  # noqa: B008
) -> dict[str, Any]:
    range_filters = parse_time_range(from_date, to_date, days)

    # Fetch all keys owned by the user
    user_keys = await APIKey.filter(owner=current_user.owner)
    user_key_ids = [k.id for k in user_keys]

    if not user_key_ids:
        return {
            "owner": current_user.owner,
            "summary": {
                "total_uploads": 0,
                "active_files": 0,
                "deleted_files": 0,
                "current_bytes_used": 0,
                "historical_bytes_sent": 0,
                "average_file_size": 0,
                "first_upload": None,
                "last_upload": None,
            },
            "api_keys_breakdown": [],
        }

    active_q = UploadedFile.filter(api_key_id__in=user_key_ids, **range_filters)
    active_stats = await active_q.annotate(
        total_count=Count("id"), total_size=Sum("file_size"), avg_size=Avg("file_size")
    ).values("total_count", "total_size", "avg_size")

    active_count = active_stats[0]["total_count"] or 0
    active_bytes = active_stats[0]["total_size"] or 0
    avg_size = active_stats[0]["avg_size"] or 0

    log_filters = {k.replace("uploaded_at", "uploaded_at"): v for k, v in range_filters.items()}
    deleted_logs = await DeletedFileLog.filter(**log_filters)

    user_deleted_logs = [
        log
        for log in deleted_logs
        if isinstance(log.meta_json, dict) and log.meta_json.get("owner") == current_user.owner
    ]

    deleted_count = len(user_deleted_logs)
    deleted_bytes = sum(log.file_size or 0 for log in user_deleted_logs)

    first_upload = await UploadedFile.filter(api_key_id__in=user_key_ids).order_by("uploaded_at").first()
    last_upload = await UploadedFile.filter(api_key_id__in=user_key_ids).order_by("-uploaded_at").first()

    breakdown_data = (
        await UploadedFile.filter(api_key_id__in=user_key_ids)
        .group_by("api_key_id")
        .annotate(file_count=Count("id"), size_sum=Sum("file_size"))
        .values("api_key_id", "file_count", "size_sum")
    )

    stats_map = {item["api_key_id"]: item for item in breakdown_data}
    keys_breakdown = []

    for key_obj in user_keys:
        key_stats = stats_map.get(key_obj.id, {"file_count": 0, "size_sum": 0})
        keys_breakdown.append(
            {
                "key_prefix": f"{key_obj.key[:6]}...",
                "role": key_obj.role.value if hasattr(key_obj.role, 'value') else str(key_obj.role),
                "active_files": key_stats["file_count"] or 0,
                "bytes_used": key_stats["size_sum"] or 0,
            }
        )

    return {
        "owner": current_user.owner,
        "summary": {
            "total_uploads": active_count + deleted_count,
            "active_files": active_count,
            "deleted_files": deleted_count,
            "current_bytes_used": active_bytes,
            "historical_bytes_sent": active_bytes + deleted_bytes,
            "average_file_size": round(avg_size, 2),
            "first_upload": str(first_upload.uploaded_at) if first_upload else None,
            "last_upload": str(last_upload.uploaded_at) if last_upload else None,
        },
        "api_keys_breakdown": keys_breakdown,
    }


@app.get("/api/metrics/admin")
async def get_admin_metrics(
    from_date: str | None = Query(None, alias="from"),
    to_date: str | None = Query(None, alias="to"),
    days: int | None = Query(None),
    current_user: APIKey = Depends(verify_api_key),  # noqa: B008
) -> dict[str, Any]:
    if current_user.role != UserRole.OWNER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Privileged administrative access required.")

    range_filters = parse_time_range(from_date, to_date, days)
    now = timezone.now()

    gen_active = (
        await UploadedFile.filter(**range_filters)
        .annotate(
            c=Count("id"), s=Sum("file_size"), max_s=Max("file_size"), min_s=Min("file_size"), a_s=Avg("file_size")
        )
        .values("c", "s", "max_s", "min_s", "a_s")
    )

    log_filters = {k.replace("uploaded_at", "uploaded_at"): v for k, v in range_filters.items()}
    gen_deleted = (
        await DeletedFileLog.filter(**log_filters).annotate(c=Count("id"), s=Sum("file_size")).values("c", "s")
    )

    ttl_expired_count = await DeletedFileLog.filter(trash_path="").count()  # Files directly purged or bypassed

    total_logical = gen_active[0]["c"] or 0
    logical_bytes = gen_active[0]["s"] or 0

    raw_uniques = await Tortoise.get_connection("default").execute_query_dict(
        "SELECT COUNT(DISTINCT file_hash) as unique_hashes, SUM(file_size) as physical_bytes FROM uploaded_files"
    )
    unique_hashes = raw_uniques[0]["unique_hashes"] or 0
    physical_bytes = raw_uniques[0]["physical_bytes"] or 0
    saved_bytes = max(0, logical_bytes - physical_bytes)
    dedup_ratio = round((saved_bytes / logical_bytes * 100), 2) if logical_bytes > 0 else 0.0

    trash_stats = (
        await DeletedFileLog.filter(purge_at__gt=now).annotate(c=Count("id"), s=Sum("file_size")).values("c", "s")
    )
    next_purge_log = await DeletedFileLog.filter(purge_at__gt=now).order_by("purge_at").first()

    total_space, used_space, free_space = shutil.disk_usage(UPLOAD_DIR)

    raw_timeline = await Tortoise.get_connection("default").execute_query_dict(
        """
            SELECT strftime('%Y-%m-%d', uploaded_at) as date_day, COUNT(id) as uploads, SUM(file_size) as size_bytes
            FROM uploaded_files GROUP BY date_day ORDER BY date_day DESC LIMIT 30
            """
    )

    top_owners = await Tortoise.get_connection("default").execute_query_dict(
        """
            SELECT ak.owner, COUNT(f.id) as total_files, SUM(f.file_size) as total_bytes
            FROM uploaded_files f JOIN api_keys ak ON f.api_key_id = ak.id
            GROUP BY ak.owner ORDER BY total_bytes DESC LIMIT 5
            """
    )

    last_24h = now - timedelta(hours=24)
    uploads_24h = await UploadedFile.filter(uploaded_at__gte=last_24h).count()

    return {
        "general_use": {
            "total_active_files": total_logical,
            "total_historical_uploads": total_logical + (gen_deleted[0]["c"] or 0),
            "total_historical_deletions": gen_deleted[0]["c"] or 0,
            "ttl_expired_files": ttl_expired_count,
            "current_occupied_bytes": logical_bytes,
            "historical_bytes_sent": logical_bytes + (gen_deleted[0]["s"] or 0),
            "average_file_size": round(gen_active[0]["a_s"] or 0, 2),
            "largest_file_bytes": gen_active[0]["max_s"] or 0,
            "smallest_file_bytes": gen_active[0]["min_s"] or 0,
        },
        "deduplication": {
            "logical_files": total_logical,
            "physical_files": unique_hashes,
            "saved_bytes": saved_bytes,
            "dedup_ratio": dedup_ratio,
        },
        "trash_can": {
            "files_awaiting_purge": trash_stats[0]["c"] or 0,
            "trash_bytes_occupied": trash_stats[0]["s"] or 0,
            "next_scheduled_purge": str(next_purge_log.purge_at) if next_purge_log else None,
        },
        "server_health_and_storage": {
            "database": "ok",
            "storage": "ok",
            "disk_total_bytes": total_space,
            "disk_used_bytes": used_space,
            "disk_free_bytes": free_space,
            "disk_percentage_used": round((used_space / total_space) * 100, 2),
            "server_uptime_seconds": round(time.time() - START_TIME, 2),
            "uploads_last_24h": uploads_24h,
        },
        "rankings": {"top_owners_by_space": top_owners},
        "timeline": raw_timeline,
    }


@app.get("/{file_path:path}", response_model=None)
async def serve_file_fallback_router(
    file_path: str,
    x_handled_by: Annotated[str | None, Header(include_in_schema=False)] = None,
    network: CloudflareMetadata = Depends(),  # noqa: B008
) -> Response | FileResponse:
    path_parts = file_path.split("/")
    if ".trash" in path_parts or any(part.startswith(".") for part in path_parts):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    target_path = (UPLOAD_DIR / file_path).resolve()
    if UPLOAD_DIR not in target_path.parents and target_path != UPLOAD_DIR:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    if not target_path.exists() or target_path.is_dir():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Requested asset file not found.")

    if UMAMI_URL_BASE and UMAMI_WEBSITE_ID and UMAMI_HOSTNAME:
        asyncio.create_task(  # noqa: RUF006
            umami.new_page_view_async(
                page_title=f"Asset View: {file_path}",
                url=f"/{file_path}",
                hostname=UMAMI_HOSTNAME,
                website_id=UMAMI_WEBSITE_ID,
                ua=str(network.ua),
                ip_address=network.ip,
            )
        )

    stat_result = target_path.stat()
    generated_etag = f'"{int(stat_result.st_mtime)}-{stat_result.st_size}"'

    shared_headers = {
        "Cache-Control": "public, max-age=2592000, immutable",
        "ETag": generated_etag,
    }
    if x_handled_by == "Caddy":
        clean_relative_path = file_path.lstrip("/")
        shared_headers["X-Accel-Redirect"] = f"/internal-media/{clean_relative_path}"
        return Response(content=None, headers=shared_headers)
    return FileResponse(path=target_path, headers=shared_headers)


@app.post("/api/sharex/config")
async def generate_sharex_config(
    request: Request,
    current_user: APIKey = Depends(verify_api_key),  # noqa: B008
) -> dict[str, Any]:
    forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    base_url_string = f"{forwarded_proto}://{request.url.netloc}"

    config_payload = {
        "Version": "14.0.1",
        "Name": f"Local File Server ({current_user.owner})",
        "DestinationType": "ImageUploader, FileUploader",
        "RequestMethod": "POST",
        "RequestURL": f"{base_url_string}/api/upload",
        "Headers": {"X-API-Key": current_user.key},
        "Body": "MultipartFormData",
        "FileFormName": "file",
        "URL": "{json:url}",
        "ThumbnailURL": "{json:thumbnail_url}",
        "DeletionURL": "{json:deletion_url}",
        "ErrorMessage": "{json:error}",
    }
    return config_payload


register_tortoise(
    app,
    db_url=DATABASE_URL,
    modules={"models": ["uploadserver.models"]},
    generate_schemas=True,
    add_exception_handlers=True,
)
