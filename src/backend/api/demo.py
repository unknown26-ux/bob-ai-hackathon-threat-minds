"""
api/demo.py — Backend orchestration engine for ThreatLens demo generation.

POST /api/demo/generate   — complete backend pipeline: scenario → alerts →
                            normalize → correlate → incidents → risk → MITRE →
                            BLUF → ALL intelligence generators → persist.
                            Frontend only needs to call this once, then fetch
                            /api/incidents to display results.

POST /api/demo/seed       — kept for backward-compat; calls generate internally.
GET  /api/demo/scenarios  — list available scenarios (for info only).
GET  /api/dashboard/stats — live dynamic statistics from DB.
"""

import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from database import get_db
from demo_data import get_demo_alerts, list_scenarios, SCENARIOS
from normalizer import normalize
from correlator import correlate
from mitre_mapper import map_techniques
from scorer import score_incident
from bluf_generator import generate_bluf
from generators.context import IncidentContext, load_context
from generators.all_generators import (
    generate_threat_intelligence,
    generate_attack_scenario,
    generate_iocs,
    generate_mitre_chain,
    generate_threat_report,
    generate_detection_rule,
    generate_response_playbook,
    generate_threat_hunting,
    generate_executive_brief,
    generate_attack_simulation,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Incident title — derived from the dominant event type in the group
# ---------------------------------------------------------------------------

_TYPE_PRIORITY = [
    "privilege_escalation",
    "data_exfiltration",
    "data_staged",
    "c2_beaconing",
    "account_manipulation",
    "authentication_success",
    "authentication_failure",
    "suspicious_script",
    "port_scan",
    "threat_intel_match",
]

_TYPE_LABEL = {
    "privilege_escalation":  "Privilege Escalation",
    "data_exfiltration":     "Data Exfiltration",
    "data_staged":           "Staged Data Transfer",
    "c2_beaconing":          "C2 Beaconing / DNS Tunneling",
    "account_manipulation":  "Account Manipulation",
    "authentication_success":"Successful Unauthorised Login",
    "authentication_failure":"Repeated Authentication Failures",
    "suspicious_script":     "Suspicious Script Execution",
    "port_scan":             "Network Reconnaissance",
    "threat_intel_match":    "Threat Intelligence Match",
}


def _incident_title(alerts: list) -> str:
    src_ips   = sorted({a.get("src_ip") for a in alerts if a.get("src_ip")})
    evt_types = {a.get("event_type") for a in alerts if a.get("event_type")}
    dominant_type = None
    for t in _TYPE_PRIORITY:
        if t in evt_types:
            dominant_type = t
            break
    if dominant_type is None and evt_types:
        dominant_type = sorted(evt_types)[0]
    label = _TYPE_LABEL.get(dominant_type, dominant_type.replace("_", " ").title()) if dominant_type else "Suspicious Activity"
    src   = src_ips[0] if src_ips else "Unknown Source"
    return f"{label} from {src}"


# ---------------------------------------------------------------------------
# Intelligence generation for one incident — runs all generators, captures
# errors per-generator without aborting the rest.
# ---------------------------------------------------------------------------

def _run_generators(ctx: IncidentContext) -> Dict[str, Any]:
    """
    Run all intelligence generators against one IncidentContext.
    Returns a dict with results and per-generator status.
    Each generator is isolated: a failure in one never stops the rest.
    """
    generators = [
        ("threat_intelligence",  generate_threat_intelligence),
        ("attack_scenario",      generate_attack_scenario),
        ("ioc_analysis",         generate_iocs),
        ("mitre_chain",          generate_mitre_chain),
        ("threat_report",        generate_threat_report),
        ("detection_rules",      generate_detection_rule),
        ("response_playbook",    generate_response_playbook),
        ("threat_hunting",       generate_threat_hunting),
        ("executive_brief",      generate_executive_brief),
        ("attack_simulation",    generate_attack_simulation),
    ]

    results: Dict[str, Any] = {}
    status:  Dict[str, str] = {}

    for key, fn in generators:
        try:
            results[key] = fn(ctx)
            status[key]  = "ok"
        except Exception as exc:
            logger.warning("Generator %s failed for incident %s: %s", key, ctx.incident_id, exc)
            results[key] = None
            status[key]  = f"error: {exc}"

    results["_generator_status"] = status
    results["_generated_at"]     = datetime.now(timezone.utc).isoformat()
    return results


# ---------------------------------------------------------------------------
# Core pipeline: normalize → correlate → persist incidents + intelligence
# ---------------------------------------------------------------------------

async def run_full_pipeline(
    db,
    raw_alerts: List[Dict],
    scenario_id: str,
    dataset_id: str,
) -> List[Dict]:
    """
    Complete backend pipeline:
      normalize → correlate → score → MITRE → BLUF → persist →
      build IncidentContext → run all generators → persist intelligence.

    Returns list of created incident summaries.
    """
    normalized = [normalize(raw) for raw in raw_alerts]
    groups     = correlate(normalized)
    created    = []

    for group in groups:
        mitre      = map_techniques(group)
        risk_score, confidence, explanation = score_incident(group, mitre)
        title      = _incident_title(group)
        bluf       = generate_bluf(title, group, mitre, explanation)

        timestamps = sorted(a.get("timestamp", "") for a in group if a.get("timestamp"))
        first_seen = timestamps[0]  if timestamps else datetime.now(timezone.utc).isoformat()
        last_seen  = timestamps[-1] if timestamps else first_seen

        # ── Step 5–8: persist incident ──
        async with db.execute(
            """INSERT INTO incidents
               (title, status, is_false_positive, risk_score, confidence,
                priority, score_explanation, mitre_techniques, bluf_summary,
                scenario, dataset_id, first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                scenario_id,
                dataset_id,
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

        # ── Step 9: build context + run all generators ──
        ctx = IncidentContext(
            incident_id       = incident_id,
            title             = title,
            status            = "open",
            risk_score        = float(risk_score),
            priority          = explanation.get("priority", "LOW"),
            confidence        = float(confidence),
            is_false_positive = bool(explanation.get("is_false_positive", False)),
            first_seen        = first_seen,
            last_seen         = last_seen,
            bluf_summary      = bluf,
            alerts            = group,
            mitre_techniques  = mitre,
            score_explanation = explanation,
        )

        intelligence = _run_generators(ctx)

        # ── Step 10: persist intelligence alongside the incident ──
        await db.execute(
            "UPDATE incidents SET intelligence = ? WHERE id = ?",
            (json.dumps(intelligence), incident_id),
        )
        await db.commit()

        gen_status = intelligence.get("_generator_status", {})
        created.append({
            "id":                incident_id,
            "title":             title,
            "risk_score":        risk_score,
            "confidence":        confidence,
            "priority":          explanation.get("priority"),
            "alert_count":       len(group),
            "mitre_count":       len(mitre),
            "is_false_positive": explanation.get("is_false_positive", False),
            "generators_ok":     sum(1 for v in gen_status.values() if v == "ok"),
            "generators_failed": sum(1 for v in gen_status.values() if v != "ok"),
        })

    return created, normalized


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

demo_router  = APIRouter(prefix="/api/demo")
stats_router = APIRouter(prefix="/api/dashboard")


# ---------------------------------------------------------------------------
# POST /api/demo/generate  — PRIMARY orchestration endpoint
# ---------------------------------------------------------------------------

@demo_router.post("/generate")
async def generate_demo():
    """
    Complete backend orchestration:
    1. Backend selects a random scenario
    2. Generates alerts
    3. Normalizes
    4. Correlates
    5. Creates incidents
    6. Scores risk / priority / confidence
    7. Maps MITRE ATT&CK
    8. Generates BLUF
    9. Runs all 10 intelligence generators
    10. Persists everything

    Frontend calls this once, then fetches /api/incidents.
    No scenario choice needed from the frontend.
    """
    dataset_id = f"DEMO-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
    raw_alerts, chosen_scenario = get_demo_alerts()   # backend selects randomly
    scenario_meta = SCENARIOS.get(chosen_scenario, {})

    db = await get_db()
    try:
        # Wipe existing data for a clean demo run
        await db.execute("DELETE FROM alerts")
        await db.execute("DELETE FROM incidents")
        try:
            await db.execute("DELETE FROM sqlite_sequence WHERE name IN ('alerts','incidents')")
        except Exception:
            pass
        await db.commit()

        created, normalized = await run_full_pipeline(db, raw_alerts, chosen_scenario, dataset_id)

        total_ok     = sum(i["generators_ok"]     for i in created)
        total_failed = sum(i["generators_failed"] for i in created)

        print("DEMO GENERATED:", {
            "scenario":      chosen_scenario,
            "scenario_name": scenario_meta.get("name", chosen_scenario),
            "alerts":        len(normalized),
            "incidents":     len(created),
            "generators_ok": total_ok,
        })

        return {
            "success":       True,
            "dataset_id":    dataset_id,
            "scenario":      chosen_scenario,
            "scenario_name": scenario_meta.get("name", chosen_scenario),
            "incidents":     len(created),
            "alerts":        len(normalized),
            "generators_ok":     total_ok,
            "generators_failed": total_failed,
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "details":       created,
        }
    except Exception as exc:
        logger.exception("generate_demo failed: %s", exc)
        return {"success": False, "error": str(exc)}
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# POST /api/demo/seed  — backward-compat alias for generate
# ---------------------------------------------------------------------------

@demo_router.post("/seed")
async def seed_demo_data():
    """Backward-compatible alias — calls generate internally."""
    result = await generate_demo()
    # Map new response shape to old shape so existing frontend code keeps working
    return {
        "status":        "seeded" if result.get("success") else "error",
        "dataset_id":    result.get("dataset_id"),
        "scenario":      result.get("scenario"),
        "scenario_name": result.get("scenario_name"),
        "incidents":     result.get("incidents", 0),
        "alerts":        result.get("alerts", 0),
        "generated_at":  result.get("generated_at"),
        "details":       result.get("details", []),
    }


@demo_router.get("/scenarios")
async def get_scenarios():
    """List all available demo scenarios (informational only)."""
    return list_scenarios()


# ---------------------------------------------------------------------------
# GET /api/dashboard/stats
# ---------------------------------------------------------------------------

@stats_router.get("/stats")
async def dashboard_stats():
    """Compute all dashboard statistics from current DB state."""
    from fastapi.responses import JSONResponse
    db = await get_db()
    try:
        async with db.execute("SELECT COUNT(*) FROM alerts") as cur:
            total_alerts = (await cur.fetchone())[0]

        async with db.execute(
            """SELECT
               COUNT(*)                                               AS total,
               SUM(CASE WHEN priority='CRITICAL' THEN 1 ELSE 0 END)  AS critical,
               SUM(CASE WHEN priority='HIGH'     THEN 1 ELSE 0 END)  AS high,
               SUM(CASE WHEN priority='MEDIUM'   THEN 1 ELSE 0 END)  AS medium,
               SUM(CASE WHEN priority='LOW'      THEN 1 ELSE 0 END)  AS low_p,
               SUM(CASE WHEN is_false_positive=0 THEN 1 ELSE 0 END)  AS genuine
               FROM incidents"""
        ) as cur:
            row = dict(await cur.fetchone())

        async with db.execute("SELECT MAX(ingested_at) FROM alerts") as cur:
            last_row = await cur.fetchone()
            last_ingested = last_row[0] if last_row else None

        print("DASHBOARD STATS:", {
            "total_alerts":    total_alerts,
            "total_incidents": row.get("total", 0) or 0,
            "critical":        row.get("critical", 0) or 0,
            "high_risk":       row.get("high", 0) or 0,
            "genuine_threats": row.get("genuine", 0) or 0,
        })

        data = {
            "total_alerts":    total_alerts,
            "total_incidents": row.get("total", 0) or 0,
            "critical":        row.get("critical", 0) or 0,
            "high_risk":       row.get("high", 0) or 0,
            "medium_risk":     row.get("medium", 0) or 0,
            "low_risk":        row.get("low_p", 0) or 0,
            "genuine_threats": row.get("genuine", 0) or 0,
            "last_updated":    last_ingested,
            "generated_at":    datetime.now(timezone.utc).isoformat(),
        }
        return JSONResponse(
            content=data,
            headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
        )
    finally:
        await db.close()
