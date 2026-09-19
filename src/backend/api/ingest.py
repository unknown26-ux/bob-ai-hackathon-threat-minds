"""
api/ingest.py — Live log ingestion endpoints for ThreatLens.

POST /api/logs/ingest        — single event
POST /api/logs/ingest/batch  — batch of events (up to 10,000)
GET  /api/ingest/metrics     — live processing metrics (JSON)
GET  /api/ingest/stream      — SSE stream of metrics (push every second)
"""

import asyncio
import json
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

import ingestion_queue as iq

router = APIRouter(prefix="/api")


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class LogEvent(BaseModel):
    timestamp:   Optional[str] = None
    source_ip:   Optional[str] = None
    src_ip:      Optional[str] = None
    dest_ip:     Optional[str] = None
    dst_ip:      Optional[str] = None
    event_type:  Optional[str] = None
    severity:    Optional[str] = None
    status_code: Optional[int] = None
    method:      Optional[str] = None
    path:        Optional[str] = None
    source:      Optional[str] = None
    indicator:   Optional[str] = None
    raw_message: Optional[str] = None
    message:     Optional[str] = None
    confidence:  Optional[int] = None

    class Config:
        extra = "allow"   # allow any extra fields through


class BatchLogRequest(BaseModel):
    events: List[LogEvent]


# ---------------------------------------------------------------------------
# Single event ingestion
# ---------------------------------------------------------------------------

@router.post("/logs/ingest", status_code=202)
async def ingest_single(event: LogEvent):
    """
    Lightweight ingestion of a single log event.
    Validates, fingerprints, enqueues and returns immediately.
    """
    raw = event.model_dump(exclude_none=False)
    # Normalise source_ip → src_ip alias for downstream pipeline
    if raw.get("source_ip") and not raw.get("src_ip"):
        raw["src_ip"] = raw["source_ip"]
    # Build a raw_message if none provided
    if not raw.get("raw_message") and not raw.get("message"):
        parts = [
            raw.get("method", ""),
            raw.get("path", ""),
            str(raw.get("status_code", "")),
            raw.get("event_type", ""),
        ]
        raw["raw_message"] = " ".join(p for p in parts if p)

    try:
        fp = iq.enqueue(raw)
    except RuntimeError as exc:
        return JSONResponse(status_code=503, content={"error": str(exc)})

    return {"status": "queued", "event_id": fp, "queue_depth": iq._queue.qsize()}


# ---------------------------------------------------------------------------
# Batch event ingestion
# ---------------------------------------------------------------------------

@router.post("/logs/ingest/batch", status_code=202)
async def ingest_batch(request: Request):
    """
    Lightweight ingestion of a batch of log events (up to 10,000).
    Accepts the same schema as single ingest, wrapped in {"events": [...]}.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON"})

    events_raw = body if isinstance(body, list) else body.get("events", [])
    if not events_raw:
        return JSONResponse(status_code=400, content={"error": "No events provided"})

    if len(events_raw) > 50_000:
        return JSONResponse(
            status_code=413,
            content={"error": "Batch too large. Maximum 50,000 events per call."},
        )

    enriched = []
    for ev in events_raw:
        if not isinstance(ev, dict):
            continue
        if ev.get("source_ip") and not ev.get("src_ip"):
            ev["src_ip"] = ev["source_ip"]
        if not ev.get("raw_message") and not ev.get("message"):
            parts = [
                ev.get("method", ""),
                ev.get("path", ""),
                str(ev.get("status_code", "")),
                ev.get("event_type", ""),
            ]
            ev["raw_message"] = " ".join(p for p in parts if p)
        enriched.append(ev)

    t0 = time.monotonic()
    try:
        fps = iq.enqueue_batch(enriched)
    except RuntimeError as exc:
        return JSONResponse(status_code=503, content={"error": str(exc)})

    accept_ms = round((time.monotonic() - t0) * 1000, 1)
    return {
        "status":       "queued",
        "accepted":     len(fps),
        "accept_ms":    accept_ms,
        "queue_depth":  iq._queue.qsize() if iq._queue else 0,
    }


# ---------------------------------------------------------------------------
# Metrics endpoint
# ---------------------------------------------------------------------------

@router.get("/ingest/metrics")
async def get_metrics():
    """Returns current ingestion metrics snapshot."""
    return iq.metrics.snapshot()


# ---------------------------------------------------------------------------
# SSE metrics stream
# ---------------------------------------------------------------------------

async def _metrics_event_generator(request: Request):
    """Yields SSE data frames with metrics every second until client disconnects."""
    while True:
        if await request.is_disconnected():
            break
        data = json.dumps(iq.metrics.snapshot())
        yield f"data: {data}\n\n"
        await asyncio.sleep(1.0)


@router.get("/ingest/stream")
async def metrics_stream(request: Request):
    """
    Server-Sent Events stream of ingestion metrics.
    The frontend connects once and receives live updates every second.
    """
    return StreamingResponse(
        _metrics_event_generator(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
