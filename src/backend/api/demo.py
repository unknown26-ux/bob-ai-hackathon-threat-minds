"""
api/demo.py — POST /api/demo/seed
Wipes existing data and runs the full pipeline on demo_data.py.
"""

import json
from fastapi import APIRouter
from database import get_db
from demo_data import DEMO_ALERTS
from normalizer import normalize
from correlator import correlate
from mitre_mapper import map_techniques
from scorer import score_incident
from bluf_generator import generate_bluf

router = APIRouter(prefix="/api/demo")


def _incident_title(alerts: list) -> str:
    src_ips = sorted({a.get("src_ip") for a in alerts if a.get("src_ip")})
    evt_types = sorted({a.get("event_type") for a in alerts if a.get("event_type")})
    dominant = (evt_types[0].replace("_", " ").title()) if evt_types else "Suspicious Activity"
    src = src_ips[0] if src_ips else "Unknown"
    return f"{dominant} from {src}"


@router.post("/seed")
async def seed_demo_data():
    """
    Clear all data and re-run the full pipeline on the built-in demo dataset.
    Returns a summary of every incident created.
    """
    db = await get_db()
    try:
        # Wipe existing data
        await db.execute("DELETE FROM alerts")
        await db.execute("DELETE FROM incidents")
        await db.execute(
            "DELETE FROM sqlite_sequence WHERE name IN ('alerts','incidents')"
        )
        await db.commit()

        normalized = [normalize(raw) for raw in DEMO_ALERTS]
        groups = correlate(normalized)
        created = []

        for group in groups:
            mitre = map_techniques(group)
            risk_score, confidence, explanation = score_incident(group, mitre)

            title = _incident_title(group)
            bluf  = generate_bluf(title, group, mitre, explanation)

            timestamps = sorted(
                a.get("timestamp", "") for a in group if a.get("timestamp")
            )
            first_seen = timestamps[0]  if timestamps else None
            last_seen  = timestamps[-1] if timestamps else None

            async with db.execute(
                """INSERT INTO incidents
                   (title, status, is_false_positive, risk_score, confidence,
                    priority, score_explanation, mitre_techniques, bluf_summary,
                    first_seen, last_seen)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    title,
                    "open",
                    int(explanation.get("is_false_positive", False)),
                    risk_score,
                    confidence,
                    explanation.get("priority", "LOW"),
                    json.dumps(explanation),
                    json.dumps(mitre),
                    bluf,
                    first_seen,
                    last_seen,
                ),
            ) as cur:
                incident_id = cur.lastrowid

            for alert in group:
                await db.execute(
                    """INSERT INTO alerts
                       (incident_id, timestamp, source, src_ip, dst_ip,
                        event_type, severity, confidence, indicator, raw_message)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        incident_id,
                        alert.get("timestamp"),
                        alert.get("source", "unknown"),
                        alert.get("src_ip"),
                        alert.get("dst_ip"),
                        alert.get("event_type", "unknown"),
                        alert.get("severity", "medium"),
                        alert.get("confidence", 50),
                        alert.get("indicator"),
                        alert.get("raw_message", ""),
                    ),
                )

            await db.commit()
            created.append({
                "id":               incident_id,
                "title":            title,
                "risk_score":       risk_score,
                "confidence":       confidence,
                "priority":         explanation.get("priority"),
                "alert_count":      len(group),
                "mitre_count":      len(mitre),
                "is_false_positive": explanation.get("is_false_positive", False),
            })

        return {
            "status":    "seeded",
            "incidents": len(created),
            "alerts":    len(normalized),
            "details":   created,
        }
    finally:
        await db.close()
