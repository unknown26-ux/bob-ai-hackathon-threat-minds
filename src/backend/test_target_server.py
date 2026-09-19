"""
test_target_server.py — Minimal local HTTP server for load testing.

Runs on port 9000.  Simulates a real web application that logs requests.

Start with:
    python test_target_server.py

Every request is forwarded as a log event to the ThreatLens ingestion API
at http://localhost:8000/api/logs/ingest (single) or /batch.

This server does NOT attack any external sites.
It accepts traffic ONLY on localhost:9000.
"""

import asyncio
import json
import random
import time
from datetime import datetime, timezone
from aiohttp import web, ClientSession


THREATLENS_INGEST_URL = "http://localhost:8000/api/logs/ingest"
THREATLENS_BATCH_URL  = "http://localhost:8000/api/logs/ingest/batch"

# Buffer log events and flush in batches for efficiency
_log_buffer: list = []
_FLUSH_THRESHOLD = 50


async def _flush_logs(session: ClientSession):
    global _log_buffer
    if not _log_buffer:
        return
    batch = _log_buffer[:_FLUSH_THRESHOLD]
    _log_buffer = _log_buffer[_FLUSH_THRESHOLD:]
    try:
        async with session.post(
            THREATLENS_BATCH_URL,
            json={"events": batch},
            timeout=5,
        ):
            pass
    except Exception:
        pass


async def handle_request(request: web.Request) -> web.Response:
    """Simulate a web application endpoint."""
    path = request.path

    # Simulate varying response codes
    r = random.random()
    if path.startswith("/admin"):
        status = 403 if r < 0.9 else 200
        event_type = "unauthorized_access"
    elif path.startswith("/login") or path.startswith("/api/auth"):
        status = 401 if r < 0.7 else 200
        event_type = "authentication_failure" if status == 401 else "authentication_success"
    elif path.startswith("/api"):
        status = 200 if r < 0.8 else 500
        event_type = "api_request"
    else:
        status = 200
        event_type = "http_request"

    src_ip = request.headers.get("X-Forwarded-For", request.remote or "127.0.0.1")
    ts = datetime.now(timezone.utc).isoformat()

    log_event = {
        "timestamp":   ts,
        "source_ip":   src_ip,
        "event_type":  event_type,
        "method":      request.method,
        "path":        path,
        "status_code": status,
        "source":      "test_web_server",
        "severity":    "high" if status in (401, 403) else "low",
        "raw_message": f"{request.method} {path} {status} from {src_ip}",
    }

    _log_buffer.append(log_event)

    if len(_log_buffer) >= _FLUSH_THRESHOLD:
        session = request.app["http_session"]
        await _flush_logs(session)

    body = json.dumps({"status": status, "path": path})
    return web.Response(
        text=body,
        status=status,
        content_type="application/json",
    )


async def on_startup(app: web.Application):
    app["http_session"] = ClientSession()
    print("✓ ThreatLens test target server started on http://localhost:9000")
    print("  Forwarding logs → http://localhost:8000/api/logs/ingest/batch")


async def on_shutdown(app: web.Application):
    await app["http_session"].close()


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_route("*", "/{path_info:.*}", handle_request)
    app.on_startup.append(on_startup)
    app.on_shutdown.append(on_shutdown)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="127.0.0.1", port=9000, access_log=None)
