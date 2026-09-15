"""
normalizer.py — Converts raw alert dicts into the standard ThreatLens event schema.
"""

from datetime import datetime, timezone
from typing import Any, Dict


VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def normalize(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accept a raw alert dict and return a normalized dict matching the
    alerts table schema. Works for SIEM, Firewall, and ThreatIntel sources.
    """

    # timestamp ---------------------------------------------------------------
    ts_raw = raw.get("timestamp") or raw.get("ts") or raw.get("time")
    try:
        ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        timestamp = ts.isoformat()
    except (ValueError, TypeError):
        timestamp = datetime.now(timezone.utc).isoformat()

    # severity ----------------------------------------------------------------
    severity = str(raw.get("severity", "medium")).lower()
    if severity not in VALID_SEVERITIES:
        severity = "medium"

    # confidence (int 0-100) --------------------------------------------------
    try:
        confidence = max(0, min(100, int(raw.get("confidence", 50))))
    except (ValueError, TypeError):
        confidence = 50

    # dst_ip — keep subnet strings as-is, None becomes None ------------------
    dst_ip = raw.get("dst_ip") or raw.get("dest_ip")
    if dst_ip is not None:
        dst_ip = str(dst_ip)

    return {
        "timestamp":   timestamp,
        "source":      str(raw.get("source", "unknown")),
        "src_ip":      raw.get("src_ip") or raw.get("source_ip"),
        "dst_ip":      dst_ip,
        "event_type":  str(raw.get("event_type", "unknown")),
        "severity":    severity,
        "confidence":  confidence,
        "indicator":   raw.get("indicator"),
        "raw_message": str(raw.get("raw_message") or raw.get("message") or ""),
    }
