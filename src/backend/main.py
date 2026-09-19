"""
main.py — ThreatLens FastAPI application entry point.

Start the server with:
    uvicorn main:app --reload --port 8000
(run from the src/backend/ directory)
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import init_db, DB_PATH
from api.health import router as health_router
from api.incidents import router as incidents_router
from api.alerts import router as alerts_router
from api.demo import demo_router, stats_router
from api.ingest import router as ingest_router
from api.loadtest import router as loadtest_router
from api.generators import router as generators_router
import ingestion_queue


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Runs once when the server starts.
    Creates the SQLite tables if they don't already exist,
    then starts the background ingestion worker.
    """
    print(f"THREATLENS DB: {os.path.abspath(DB_PATH)}")
    await init_db()
    await ingestion_queue.start_worker()
    yield
    await ingestion_queue.stop_worker()


app = FastAPI(
    title="ThreatLens",
    description="Threat Intelligence Correlation & Alert Prioritisation Assistant",
    version="0.3.0",
    lifespan=lifespan,
)

# Allow the React dev server (port 5173) and load test (port 9000) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:9000",
        "http://127.0.0.1:9000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Routers -----------------------------------------------------------------
app.include_router(health_router)
app.include_router(incidents_router)
app.include_router(alerts_router)
app.include_router(demo_router)
app.include_router(stats_router)
app.include_router(ingest_router)
app.include_router(loadtest_router)
app.include_router(generators_router)
