"""
generators/context.py — IncidentContext: shared data loaded once per generator call.

Every generator receives an IncidentContext. This avoids duplicate DB queries
and ensures all generators reason about the same consistent incident snapshot.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from database import get_db


@dataclass
class IncidentContext:
    incident_id:    int
    title:          str
    status:         str
    risk_score:     float
    priority:       str
    confidence:     float
    is_false_positive: bool
    first_seen:     str
    last_seen:      str
    bluf_summary:   Optional[str]

    alerts:         List[Dict[str, Any]] = field(default_factory=list)
    mitre_techniques: List[Dict[str, Any]] = field(default_factory=list)
    score_explanation: Dict[str, Any]   = field(default_factory=dict)

    # Derived convenience fields (populated after init)
    source_ips:     List[str] = field(default_factory=list)
    dest_ips:       List[str] = field(default_factory=list)
    event_types:    List[str] = field(default_factory=list)
    indicators:     List[str] = field(default_factory=list)
    sources:        List[str] = field(default_factory=list)

    def __post_init__(self):
        self.source_ips  = sorted({a.get("src_ip")     for a in self.alerts if a.get("src_ip")})
        self.dest_ips    = sorted({a.get("dst_ip")     for a in self.alerts if a.get("dst_ip")})
        self.event_types = sorted({a.get("event_type") for a in self.alerts if a.get("event_type")})
        self.indicators  = sorted({a.get("indicator")  for a in self.alerts if a.get("indicator")})
        self.sources     = sorted({a.get("source")     for a in self.alerts if a.get("source")})

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    @property
    def has_threat_intel(self) -> bool:
        return bool(self.score_explanation.get("threat_intel_match"))

    @property
    def mitre_ids(self) -> List[str]:
        return [t.get("technique_id", "") for t in self.mitre_techniques]

    @property
    def severity_profile(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for a in self.alerts:
            sev = a.get("severity", "unknown")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def dominant_severity(self) -> str:
        for sev in ("critical", "high", "medium", "low"):
            if any(a.get("severity") == sev for a in self.alerts):
                return sev
        return "low"

    def timeline(self) -> List[Dict[str, Any]]:
        """Sorted list of (timestamp, event_type, src_ip, raw_message) dicts."""
        return sorted(
            [
                {
                    "timestamp":  a.get("timestamp", ""),
                    "event_type": a.get("event_type", ""),
                    "src_ip":     a.get("src_ip", ""),
                    "dst_ip":     a.get("dst_ip", ""),
                    "severity":   a.get("severity", ""),
                    "message":    a.get("raw_message", ""),
                }
                for a in self.alerts
            ],
            key=lambda x: x["timestamp"],
        )

    def to_dict(self) -> Dict[str, Any]:
        false_positive = self.score_explanation.get("false_positive") if isinstance(self.score_explanation, dict) else None
        return {
            "incident_id":      self.incident_id,
            "title":            self.title,
            "status":           self.status,
            "risk_score":       self.risk_score,
            "priority":         self.priority,
            "confidence":       self.confidence,
            "is_false_positive": self.is_false_positive,
            "false_positive":   false_positive,
            "first_seen":       self.first_seen,
            "last_seen":        self.last_seen,
            "alert_count":      self.alert_count,
            "source_ips":       self.source_ips,
            "dest_ips":         self.dest_ips,
            "event_types":      self.event_types,
            "indicators":       self.indicators,
            "mitre_techniques": self.mitre_techniques,
            "score_explanation": self.score_explanation,
            "bluf_summary":     self.bluf_summary,
        }


async def load_context(incident_id: int) -> Optional[IncidentContext]:
    """
    Load an incident and all its alerts from the DB, returning an IncidentContext.
    Returns None if the incident does not exist.
    """
    db = await get_db()
    try:
        async with db.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        d = dict(row)

        async with db.execute(
            "SELECT * FROM alerts WHERE incident_id = ? ORDER BY timestamp ASC",
            (incident_id,),
        ) as cur:
            alert_rows = await cur.fetchall()

        alerts = [dict(r) for r in alert_rows]

        def _parse(v):
            if v and isinstance(v, str):
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return v or {}

        return IncidentContext(
            incident_id       = d["id"],
            title             = d["title"],
            status            = d["status"],
            risk_score        = float(d.get("risk_score", 0)),
            priority          = d.get("priority", "LOW"),
            confidence        = float(d.get("confidence", 50)),
            is_false_positive = bool(d.get("is_false_positive", 0)),
            first_seen        = d.get("first_seen", ""),
            last_seen         = d.get("last_seen", ""),
            bluf_summary      = d.get("bluf_summary"),
            alerts            = alerts,
            mitre_techniques  = _parse(d.get("mitre_techniques")) or [],
            score_explanation = _parse(d.get("score_explanation")) or {},
        )
    finally:
        await db.close()
