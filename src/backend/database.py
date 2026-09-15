"""
database.py — SQLite database setup for ThreatLens.

Uses aiosqlite for async access. The database file (threatlens.db) is
created automatically on first startup in the same directory as this file.

Tables:
  alerts    — individual normalised security alerts from any source
  incidents — correlated groups of related alerts, enriched with scoring
"""

import aiosqlite
import os

# Path to the SQLite database file, sitting next to this module
DB_PATH = os.path.join(os.path.dirname(__file__), "threatlens.db")

# incidents table — must be created before alerts (FK reference)
CREATE_INCIDENTS_TABLE = """
CREATE TABLE IF NOT EXISTS incidents (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    title             TEXT    NOT NULL,
    status            TEXT    NOT NULL DEFAULT 'open',
    is_false_positive INTEGER NOT NULL DEFAULT 0,
    risk_score        REAL    NOT NULL DEFAULT 0.0,
    confidence        REAL    NOT NULL DEFAULT 0.0,
    priority          TEXT    NOT NULL DEFAULT 'LOW',
    score_explanation TEXT,
    mitre_techniques  TEXT,
    bluf_summary      TEXT,
    first_seen        TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen         TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""

# alerts table — stores one normalised alert per row
CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id   INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    timestamp     TEXT    NOT NULL,
    source        TEXT    NOT NULL DEFAULT 'unknown',
    src_ip        TEXT,
    dst_ip        TEXT,
    event_type    TEXT    NOT NULL DEFAULT 'unknown',
    severity      TEXT    NOT NULL DEFAULT 'medium',
    confidence    INTEGER NOT NULL DEFAULT 50,
    indicator     TEXT,
    raw_message   TEXT    NOT NULL DEFAULT '',
    ingested_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


async def get_db() -> aiosqlite.Connection:
    """
    Open and return an aiosqlite connection.
    Row factory is set so rows behave like dicts.
    """
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = aiosqlite.Row
    return conn


async def init_db() -> None:
    """
    Create all tables if they do not already exist.
    Called once at application startup. Safe to call multiple times.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        # incidents first — alerts FK references it
        await conn.execute(CREATE_INCIDENTS_TABLE)
        await conn.execute(CREATE_ALERTS_TABLE)
        await conn.commit()
