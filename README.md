# File Server API

A personal-ish file hosting server.

The application provides authenticated uploads, automatic metadata removal, file deduplication through hard links, temporary file expiration, deletion tokens, API key management, and usage metrics.

## Endpoints

| Endpoint                  | Description                             |
|---------------------------|-----------------------------------------|
| `POST /api/upload`        | Upload a file with metadata cleaning    |
| `POST /api/uploaddoxx`    | Upload a file without metadata cleaning |
| `GET /api/delete/{token}` | Delete a file using its deletion token  |
| `POST /api/keys`          | Create a new API key (OWNER only)       |
| `GET /api/metrics/user`   | User metrics                            |
| `GET /api/metrics/admin`  | Administrator metrics                   |
| `GET /{path}`             | Download a file                         |
| `POST /api/sharex/config` | Easy way to create sharex config        |

## Upload Options

Uploads support:

* Tags
* Upload scopes through the `X-Name` header
* Optional `ttl_seconds`
* An automatic role and owner tags

## CLI

Run the API:

```bash
uv main.py
```

The first API key:

```bash
uv run main.py create-key --owner admin --role owner
```

Create an API key:

```bash
uv main.py create-key --owner alice --role vip --max-size-mb 1024
```

## Reverse Proxy

This application is designed to run behind a reverse proxy. The recommended setup uses Caddy with `file_server` and internal redirects for efficient static file delivery, reducing the load on the FastAPI application.

It can also be deployed behind other reverse proxies such as Nginx, or run directly without a reverse proxy if preferred.

Example Caddy configuration:

```text
upload.domain {
    encode gzip zstd

    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
    }

    handle /api* {
        reverse_proxy upload_server:8000
    }

    handle {
        reverse_proxy upload_server:8000 {
            header_up X-Handled-By "Caddy"

            @accel {
                header X-Accel-Redirect *
            }

            handle_response @accel {
                vars back_to_caddy {rp.header.X-Accel-Redirect}
                rewrite * {vars.back_to_caddy}
                uri strip_prefix /internal-media
                root * /uploads
                file_server {
                    hide .*
                }
            }
        }
    }

}
```

## Analytics

Umami events are generated for uploads, downloads, deletions, API key creation, and page views.

## Metrics

The API provides user and administrator metrics including uploads, deletions, storage usage, disk information, upload history, deduplication statistics, server uptime, and owner rankings.

## Roles

| Role   | Description                |
|--------|----------------------------|
| OWNER  | Full administrative access |
| VIP    | Double upload size limit   |
| NORMAL | Standard user              |

## Metadata Cleaning

The standard upload endpoint removes metadata from supported image and media formats before saving the file.

Supported images:

* jpg
* jpeg
* png
* tif
* tiff
* webp
* heic
* heif
* avif

Supported media:

* mp4
* mov
* m4v
* mp3

The `/api/uploaddoxx` endpoint stores files without modifying metadata.

## Background Tasks

A background task runs every 60 seconds to delete expired uploads and permanently purge files waiting in the trash.
