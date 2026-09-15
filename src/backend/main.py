"""
main.py — ThreatLens FastAPI application entry point.

Start the server with:
    uvicorn main:app --reload --port 8000
(run from the src/backend/ directory)
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import init_db
from api.health import router as health_router
from api.incidents import router as incidents_router
from api.alerts import router as alerts_router
from api.demo import router as demo_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Runs once when the server starts.
    Creates the SQLite tables if they don't already exist.
    """
    await init_db()
    yield


app = FastAPI(
    title="ThreatLens",
    description="Threat Intelligence Correlation & Alert Prioritisation Assistant",
    version="0.1.0",
    lifespan=lifespan,
)

# Allow the React dev server (port 5173) to call the API during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Routers -----------------------------------------------------------------
app.include_router(health_router)
app.include_router(incidents_router)
app.include_router(alerts_router)
app.include_router(demo_router)
