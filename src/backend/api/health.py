"""
api/health.py — Health check endpoint.

GET /api/health
Returns a simple JSON response confirming the service is running.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/api")


@router.get("/health")
async def health():
    """Returns service health status."""
    return {"status": "healthy", "service": "ThreatLens"}
