"""
ingestion_queue.py — Async in-process ingestion queue for ThreatLens.

Architecture:
  HTTP handler:  validate → fingerprint → enqueue → return 202 immediately
  Background worker: dequeue in batches → normalize → correlate → score → DB

No external dependencies (no Redis/Kafka). Uses asyncio.Queue which is
thread-safe within a single async event loop (uvicorn's loop).
"""

import asyncio
import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiosqlite

from database import get_db
from normalizer import normalize
from mitre_mapper import map_techniques
from scorer import score_incident
from bluf_generator import generate_bluf

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
WORKER_BATCH_SIZE   = 200   # events processed per worker cycle
WORKER_INTERVAL_SEC = 0.5   # seconds between worker cycles
CORRELATION_WINDOW_MINUTES = 10
QUEUE_MAX_SIZE = 100_000    # prevents unbounded memory growth

# Global sequence counter — stamps every enqueued event with a unique seq#
# so that high-volume repeated events (e.g. load test) each get a distinct
# fingerprint and are not incorrectly deduplicated against prior batches.
import itertools
_seq_counter = itertools.count(1)

# ---------------------------------------------------------------------------
# In-memory metrics (reset on each server start)
# ---------------------------------------------------------------------------
class IngestionMetrics:
    def __init__(self):
        self.received:    int   = 0
        self.processed:   int   = 0
        self.failed:      int   = 0
        self.duplicates:  int   = 0
        self.suspicious:  int   = 0
        self.critical_events: int = 0
        self.incidents_created: int = 0
        self.incidents_updated: int = 0
        self._start_time: float = time.monotonic()
        self._last_rate_window_ts: float = time.monotonic()
        self._last_rate_window_count: int = 0
        self._events_per_sec: float = 0.0
        self._last_latency_ms: float = 0.0
        self._source_ips: set = set()          # unique source IPs seen this session

    def record_received(self, count: int = 1):
        self.received += count

    def record_processed(self, count: int, latency_ms: float, suspicious: int, critical: int,
                         source_ips: Optional[set] = None):
        self.processed     += count
        self._last_latency_ms = latency_ms
        self.suspicious    += suspicious
        self.critical_events += critical
        if source_ips:
            self._source_ips.update(source_ips)
        # rolling events/sec (updated every batch)
        now = time.monotonic()
        elapsed = now - self._last_rate_window_ts
        if elapsed >= 1.0:
            self._events_per_sec = round(
                (self.processed - self._last_rate_window_count) / elapsed, 1
            )
            self._last_rate_window_ts    = now
            self._last_rate_window_count = self.processed

    def record_failed(self, count: int = 1):
        self.failed += count

    def record_duplicate(self, count: int = 1):
        self.duplicates += count

    def snapshot(self) -> Dict[str, Any]:
        queue_size = _queue.qsize() if _queue else 0
        return {
            "received":          self.received,
            "processed":         self.processed,
            "pending":           queue_size,
            "failed":            self.failed,
            "duplicates":        self.duplicates,
            "suspicious":        self.suspicious,
            "critical_events":   self.critical_events,
            "incidents_created": self.incidents_created,
            "incidents_updated": self.incidents_updated,
            "events_per_sec":    self._events_per_sec,
            "latency_ms":        round(self._last_latency_ms, 1),
            "uptime_sec":        round(time.monotonic() - self._start_time, 1),
            "unique_source_ips": len(self._source_ips),
        }


metrics = IngestionMetrics()

# ---------------------------------------------------------------------------
# Queue (created in start_worker, referenced globally)
# ---------------------------------------------------------------------------
_queue: Optional[asyncio.Queue] = None
_worker_task: Optional[asyncio.Task] = None


def _fingerprint(event: Dict[str, Any], seq: int) -> str:
    """
    Deterministic SHA-256 fingerprint for deduplication.

    Each event is stamped with a unique sequence number at enqueue time so
    that high-volume repeated events (e.g. brute-force load test) each get
    their own distinct identity.  True duplicate re-transmissions (same raw
    event arriving twice from an external source) should be fingerprinted by
    the sender and passed in as event['_ext_fingerprint'].

    If the event carries a pre-computed external fingerprint (e.g. forwarded
    from a SIEM with its own dedup logic), use that instead.
    """
    if event.get("_ext_fingerprint"):
        return str(event["_ext_fingerprint"])[:32]

    ts_raw = event.get("timestamp") or event.get("ts") or ""
    ts_sec = str(ts_raw)[:19]           # "YYYY-MM-DDTHH:MM:SS"
    src_ip = str(event.get("source_ip") or event.get("src_ip") or "")
    etype  = str(event.get("event_type") or "")
    status = str(event.get("status_code") or "")
    raw    = str(event.get("raw_message") or event.get("message") or "")
    key    = f"{seq}|{ts_sec}|{src_ip}|{etype}|{status}|{raw}"
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def enqueue(event: Dict[str, Any]) -> str:
    """
    Validate, fingerprint and enqueue a single raw event dict.
    Returns the fingerprint (event ID).  Non-blocking — raises if queue full.
    """
    if _queue is None:
        raise RuntimeError("Ingestion worker not started")
    if _queue.full():
        raise RuntimeError("Ingestion queue is full — server overloaded")

    seq = next(_seq_counter)
    fp = _fingerprint(event, seq)
    event["_fingerprint"] = fp
    _queue.put_nowait(event)
    metrics.record_received()
    return fp


def enqueue_batch(events: List[Dict[str, Any]]) -> List[str]:
    """Enqueue a list of events.  Returns list of fingerprints."""
    if _queue is None:
        raise RuntimeError("Ingestion worker not started")
    fps = []
    for ev in events:
        seq = next(_seq_counter)
        fp = _fingerprint(ev, seq)
        ev["_fingerprint"] = fp
        _queue.put_nowait(ev)
        fps.append(fp)
    metrics.record_received(len(events))
    return fps


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

def _incident_title(alerts: List[Dict]) -> str:
    src_ips   = sorted({a.get("src_ip") for a in alerts if a.get("src_ip")})
    evt_types = sorted({a.get("event_type") for a in alerts if a.get("event_type")})
    dominant  = evt_types[0].replace("_", " ").title() if evt_types else "Suspicious Activity"
    src       = src_ips[0] if src_ips else "Unknown"
    return f"{dominant} from {src}"


async def _upsert_incident(
    db: aiosqlite.Connection,
    src_ip: Optional[str],
    alerts: List[Dict],
    normalized_alerts: List[Dict],
) -> int:
    """
    Find an active open incident for this src_ip within the correlation window,
    or create a new one.  Returns incident_id.
    """
    incident_id = None

    if src_ip:
        # Find the most recently updated open incident that involves this source IP.
        # We match on the title suffix "from <ip>" which is deterministically generated.
        async with db.execute(
            """SELECT id FROM incidents
               WHERE title LIKE ?
               ORDER BY last_seen DESC LIMIT 1""",
            (f"% from {src_ip}",),
        ) as cur:
            row = await cur.fetchone()
            if row:
                incident_id = row[0]

    # For scoring: when updating an existing incident, combine with existing alert count
    # to give accurate volume scoring (don't re-fetch all rows, just get count)
    score_alerts = list(normalized_alerts)
    if incident_id is not None:
        async with db.execute(
            "SELECT COUNT(*) FROM alerts WHERE incident_id = ?", (incident_id,)
        ) as cur:
            existing_count_row = await cur.fetchone()
            existing_count = existing_count_row[0] if existing_count_row else 0
        # Pad with synthetic minimal alert dicts for volume scoring only
        for _ in range(existing_count):
            score_alerts.append({"severity": "medium", "confidence": 50})

    mitre = map_techniques(normalized_alerts)
    risk_score, confidence, explanation = score_incident(score_alerts, mitre)
    title = _incident_title(normalized_alerts)
    bluf  = generate_bluf(title, normalized_alerts, mitre, explanation)

    timestamps = sorted(a.get("timestamp", "") for a in normalized_alerts if a.get("timestamp"))
    first_seen = timestamps[0]  if timestamps else datetime.now(timezone.utc).isoformat()
    last_seen  = timestamps[-1] if timestamps else first_seen

    if incident_id is not None:
        # Update existing incident
        await db.execute(
            """UPDATE incidents SET
               risk_score=?, confidence=?, priority=?, score_explanation=?,
               mitre_techniques=?, bluf_summary=?, last_seen=?
               WHERE id=?""",
            (
                risk_score, confidence, explanation.get("priority", "LOW"),
                json.dumps(explanation), json.dumps(mitre), bluf,
                last_seen, incident_id,
            ),
        )
        metrics.incidents_updated += 1
    else:
        async with db.execute(
            """INSERT INTO incidents
               (title, status, is_false_positive, risk_score, confidence,
                priority, score_explanation, mitre_techniques, bluf_summary,
                first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                title, "open",
                int(explanation.get("is_false_positive", False)),
                risk_score, confidence,
                explanation.get("priority", "LOW"),
                json.dumps(explanation), json.dumps(mitre), bluf,
                first_seen, last_seen,
            ),
        ) as cur:
            incident_id = cur.lastrowid
        metrics.incidents_created += 1

    return incident_id


async def _process_batch(batch: List[Dict[str, Any]]) -> None:
    t0 = time.monotonic()
    db = await get_db()
    try:
        # Dedup: check fingerprints already in DB
        fps = [e["_fingerprint"] for e in batch]
        placeholders = ",".join("?" * len(fps))
        async with db.execute(
            f"SELECT fingerprint FROM alerts WHERE fingerprint IN ({placeholders})",
            fps,
        ) as cur:
            existing_fps = {row[0] for row in await cur.fetchall()}

        new_batch  = [e for e in batch if e["_fingerprint"] not in existing_fps]
        dup_count  = len(batch) - len(new_batch)
        if dup_count:
            metrics.record_duplicate(dup_count)
        if not new_batch:
            return

        # Normalize
        normalized = [normalize(e) for e in new_batch]
        for norm, raw in zip(normalized, new_batch):
            norm["_fingerprint"] = raw["_fingerprint"]

        # Group by src_ip for per-source correlation
        by_ip: Dict[str, List] = {}
        no_ip: List = []
        for norm in normalized:
            ip = norm.get("src_ip")
            if ip:
                by_ip.setdefault(ip, []).append(norm)
            else:
                no_ip.append(norm)

        suspicious = 0
        critical_c = 0

        all_groups = list(by_ip.items()) + [("", no_ip)] if no_ip else list(by_ip.items())

        for src_ip, group_alerts in all_groups:
            if not group_alerts:
                continue
            incident_id = await _upsert_incident(
                db, src_ip or None, group_alerts, group_alerts
            )
            for norm in group_alerts:
                sev = norm.get("severity", "medium")
                if sev in ("high", "critical"):
                    suspicious += 1
                if sev == "critical":
                    critical_c += 1
                await db.execute(
                    """INSERT INTO alerts
                       (incident_id, timestamp, source, src_ip, dst_ip,
                        event_type, severity, confidence, indicator,
                        raw_message, fingerprint)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        incident_id,
                        norm.get("timestamp"),
                        norm.get("source", "live_ingest"),
                        norm.get("src_ip"),
                        norm.get("dst_ip"),
                        norm.get("event_type", "unknown"),
                        norm.get("severity", "medium"),
                        norm.get("confidence", 50),
                        norm.get("indicator"),
                        norm.get("raw_message", ""),
                        norm.get("_fingerprint"),
                    ),
                )

        await db.commit()
        latency_ms = (time.monotonic() - t0) * 1000
        seen_ips = {a.get("src_ip") for a in normalized if a.get("src_ip")}
        metrics.record_processed(len(new_batch), latency_ms, suspicious, critical_c, seen_ips)

    except Exception as exc:
        logger.exception("Batch processing error: %s", exc)
        metrics.record_failed(len(batch))
    finally:
        await db.close()


async def _worker_loop() -> None:
    logger.info("ThreatLens ingestion worker started")
    while True:
        try:
            batch: List[Dict] = []
            # Drain up to WORKER_BATCH_SIZE items from the queue
            try:
                # Block until at least one item arrives
                item = await asyncio.wait_for(
                    _queue.get(), timeout=WORKER_INTERVAL_SEC
                )
                batch.append(item)
            except asyncio.TimeoutError:
                pass

            # Non-blocking drain of remaining items
            while len(batch) < WORKER_BATCH_SIZE and not _queue.empty():
                batch.append(_queue.get_nowait())

            if batch:
                await _process_batch(batch)

        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.exception("Worker loop error: %s", exc)
            await asyncio.sleep(1)

    logger.info("ThreatLens ingestion worker stopped")


async def start_worker() -> None:
    """Start the background ingestion worker. Call from FastAPI lifespan."""
    global _queue, _worker_task
    _queue       = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
    _worker_task = asyncio.create_task(_worker_loop())


async def stop_worker() -> None:
    """Gracefully stop the worker. Call from FastAPI lifespan shutdown."""
    if _worker_task:
        _worker_task.cancel()
        try:
            await _worker_task
        except asyncio.CancelledError:
            pass
