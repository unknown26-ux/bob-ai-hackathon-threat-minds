"""
api/incidents.py — GET /api/incidents and GET /api/incidents/{id}
"""

import json
from typing import Optional
from fastapi import APIRouter, HTTPException
from database import get_db

router = APIRouter(prefix="/api")


def _parse_json_col(value):
    if value and isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            pass
    return value or []


@router.get("/incidents")
async def list_incidents(
    status: Optional[str] = None,
    min_score: Optional[float] = None,
):
    """All incidents ordered by risk_score descending."""
    db = await get_db()
    try:
        query = "SELECT * FROM incidents"
        conditions, params = [], []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if min_score is not None:
            conditions.append("risk_score >= ?")
            params.append(min_score)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY risk_score DESC"

        async with db.execute(query, params) as cur:
            rows = await cur.fetchall()

        result = []
        for r in rows:
            d = dict(r)
            d["mitre_techniques"]  = _parse_json_col(d.get("mitre_techniques"))
            d["score_explanation"] = _parse_json_col(d.get("score_explanation"))
            d["is_false_positive"] = bool(d.get("is_false_positive", 0))
            result.append(d)
        return result
    finally:
        await db.close()


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: int):
    """Single incident with all correlated alerts."""
    db = await get_db()
    try:
        async with db.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            raise HTTPException(404, f"Incident {incident_id} not found")

        d = dict(row)
        d["mitre_techniques"]  = _parse_json_col(d.get("mitre_techniques"))
        d["score_explanation"] = _parse_json_col(d.get("score_explanation"))
        d["is_false_positive"] = bool(d.get("is_false_positive", 0))

        async with db.execute(
            "SELECT * FROM alerts WHERE incident_id = ? ORDER BY timestamp ASC",
            (incident_id,),
        ) as cur:
            alert_rows = await cur.fetchall()

        d["alerts"] = [dict(r) for r in alert_rows]
        return d
    finally:
        await db.close()
