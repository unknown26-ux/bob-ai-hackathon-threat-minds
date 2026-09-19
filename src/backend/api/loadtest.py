"""
api/loadtest.py — Safe local load test simulator for ThreatLens.

POST /api/loadtest/run   — run a load test against localhost:9000
GET  /api/loadtest/status — get current test status

IMPORTANT: This simulator only generates traffic against localhost:9000.
It does NOT attack any external websites.
"""

import asyncio
import json
import random
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import ingestion_queue as iq

router = APIRouter(prefix="/api/loadtest")

# ---------------------------------------------------------------------------
# Load test state
# ---------------------------------------------------------------------------
_test_state: Dict[str, Any] = {
    "running":       False,
    "events_sent":   0,
    "events_target": 0,
    "start_time":    None,
    "end_time":      None,
    "completed":     False,
    "error":         None,
}

_test_task: Optional[asyncio.Task] = None


# ---------------------------------------------------------------------------
# Synthetic event generation
# ---------------------------------------------------------------------------

# Simulated attacker source IPs — realistic multi-source scenario
ATTACKER_PROFILES = [
    {
        "ip":    "185.22.14.8",
        "share": 0.35,   # 35% of events
        "profile": "brute_force",
        "paths": ["/login", "/api/auth", "/wp-login.php", "/admin/login"],
        "methods": ["POST"],
        "severity": "high",
    },
    {
        "ip":    "10.20.5.12",
        "share": 0.25,
        "profile": "port_scan",
        "paths": ["/admin", "/phpmyadmin", "/.env", "/config", "/.git"],
        "methods": ["GET"],
        "severity": "high",
    },
    {
        "ip":    "172.16.4.20",
        "share": 0.20,
        "profile": "api_abuse",
        "paths": ["/api/users", "/api/data", "/api/export", "/api/admin"],
        "methods": ["GET", "POST", "DELETE"],
        "severity": "medium",
    },
    {
        "ip":    "203.0.113.55",
        "share": 0.12,
        "profile": "recon",
        "paths": ["/robots.txt", "/sitemap.xml", "/../../../etc/passwd", "/wp-content"],
        "methods": ["GET"],
        "severity": "medium",
    },
    {
        "ip":    "91.108.56.200",
        "share": 0.08,
        "profile": "credential_stuffing",
        "paths": ["/login", "/oauth/token", "/api/v1/auth"],
        "methods": ["POST"],
        "severity": "critical",
    },
]

# Normalise shares to pick randomly
_CUMULATIVE = []
acc = 0.0
for _p in ATTACKER_PROFILES:
    acc += _p["share"]
    _CUMULATIVE.append(acc)


def _pick_profile() -> Dict:
    r = random.random()
    for i, c in enumerate(_CUMULATIVE):
        if r <= c:
            return ATTACKER_PROFILES[i]
    return ATTACKER_PROFILES[-1]


PROFILE_EVENT_TYPES = {
    "brute_force":          ["authentication_failure", "authentication_failure", "authentication_failure", "authentication_success"],
    "port_scan":            ["port_scan", "unauthorized_access", "http_request"],
    "api_abuse":            ["api_request", "data_access", "suspicious_request"],
    "recon":                ["http_request", "suspicious_request", "directory_traversal"],
    "credential_stuffing":  ["authentication_failure", "authentication_failure", "brute_force_attempt"],
}

STATUS_MAP = {
    "authentication_failure": [401, 401, 401, 403],
    "authentication_success": [200],
    "port_scan":              [404, 403, 200, 500],
    "unauthorized_access":    [403, 401],
    "api_request":            [200, 200, 500, 429],
    "data_access":            [200, 403],
    "suspicious_request":     [400, 404, 403],
    "directory_traversal":    [404, 403, 200],
    "brute_force_attempt":    [401, 401, 403],
    "http_request":           [200, 404, 500],
}


def _make_event(ts: str) -> Dict[str, Any]:
    profile    = _pick_profile()
    event_type = random.choice(PROFILE_EVENT_TYPES.get(profile["profile"], ["http_request"]))
    status     = random.choice(STATUS_MAP.get(event_type, [200]))
    path       = random.choice(profile["paths"])
    method     = random.choice(profile["methods"])
    severity   = profile["severity"] if status in (401, 403, 500) else "low"

    return {
        "timestamp":   ts,
        "source_ip":   profile["ip"],
        "event_type":  event_type,
        "method":      method,
        "path":        path,
        "status_code": status,
        "source":      "load_test_simulator",
        "severity":    severity,
        "confidence":  random.randint(60, 95),
        "raw_message": f"{method} {path} {status} from {profile['ip']}",
    }


# ---------------------------------------------------------------------------
# Load test runner
# ---------------------------------------------------------------------------

BATCH_CHUNK = 200  # send to ingestion pipeline in chunks of 200


async def _run_test(target: int) -> None:
    global _test_state
    _test_state.update(
        running=True,
        events_sent=0,
        events_target=target,
        start_time=time.monotonic(),
        end_time=None,
        completed=False,
        error=None,
    )

    try:
        sent   = 0
        t_start = datetime.now(timezone.utc)
        base_ts = t_start.isoformat()

        while sent < target:
            chunk_size = min(BATCH_CHUNK, target - sent)
            now_ts = datetime.now(timezone.utc).isoformat()
            batch  = [_make_event(now_ts) for _ in range(chunk_size)]

            try:
                iq.enqueue_batch(batch)
                sent += chunk_size
                _test_state["events_sent"] = sent
            except RuntimeError:
                # Queue full — back off briefly
                await asyncio.sleep(0.1)
                continue

            # Yield control so the ingestion worker can process
            await asyncio.sleep(0)

    except Exception as exc:
        _test_state["error"] = str(exc)
    finally:
        _test_state["end_time"]  = time.monotonic()
        _test_state["running"]   = False
        _test_state["completed"] = True


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

class LoadTestRequest(BaseModel):
    count: int = 1000   # number of events to generate


@router.post("/run")
async def run_load_test(req: LoadTestRequest):
    global _test_task

    if _test_state.get("running"):
        return JSONResponse(
            status_code=409,
            content={"error": "A load test is already running"},
        )

    if req.count < 1 or req.count > 50_000:
        return JSONResponse(
            status_code=400,
            content={"error": "count must be between 1 and 50,000"},
        )

    _test_task = asyncio.create_task(_run_test(req.count))

    return {
        "status":        "started",
        "events_target": req.count,
        "note":          "Only targeting localhost — no external traffic",
    }


@router.get("/status")
async def get_test_status():
    state   = dict(_test_state)
    metrics = iq.metrics.snapshot()

    elapsed = None
    if state.get("start_time"):
        end = state.get("end_time") or time.monotonic()
        elapsed = round(end - state["start_time"], 2)

    avg_rate = None
    if elapsed and elapsed > 0 and state.get("events_sent", 0) > 0:
        avg_rate = round(state["events_sent"] / elapsed, 1)

    return {
        "test":    state,
        "metrics": metrics,
        "elapsed_sec":  elapsed,
        "avg_rate_eps": avg_rate,
    }
