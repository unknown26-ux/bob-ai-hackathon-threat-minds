"""
api/alerts.py — REST endpoint for raw alerts.

GET /api/alerts — paginated list of all ingested alerts
"""

from typing import Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from database import get_db

router = APIRouter(prefix="/api")

_NO_CACHE = {"Cache-Control": "no-store, no-cache, must-revalidate"}


@router.get("/alerts")
async def list_alerts(
    limit: int = 100,
    offset: int = 0,
    src_ip: Optional[str] = None,
):
    """
    Returns ingested alerts ordered by timestamp descending.

    Optional query params:
      ?src_ip=203.0.113.42    filter by source IP
      ?limit=50&offset=0      pagination
    """
    db = await get_db()
    try:
        query = "SELECT * FROM alerts"
        conditions = []
        params = []

        if src_ip:
            conditions.append("src_ip = ?")
            params.append(src_ip)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params += [limit, offset]

        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
        return JSONResponse(content=[dict(r) for r in rows], headers=_NO_CACHE)
    finally:
        await db.close()
