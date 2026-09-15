"""
models.py — Pydantic models for ThreatLens.

These models define the shape of data flowing through the API.
They are intentionally kept minimal so each Phase can extend them cleanly.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Alert models
# ---------------------------------------------------------------------------

class AlertBase(BaseModel):
    """Fields shared by all alert representations."""
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    severity: str = "medium"           # low | medium | high | critical
    category: Optional[str] = None
    raw_message: str
    source_format: str = "json"        # json | cef | syslog


class AlertCreate(AlertBase):
    """Used when ingesting a new alert (no id yet)."""
    pass


class Alert(AlertBase):
    """Full alert as returned from the database."""
    id: int
    incident_id: Optional[int] = None
    ingested_at: datetime

    class Config:
        from_attributes = True  # allows construction from SQLite Row objects


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique reference
# ---------------------------------------------------------------------------

class MITRETechnique(BaseModel):
    """A single MITRE ATT&CK technique attached to an incident."""
    technique_id: str    # e.g. "T1078"
    name: str            # e.g. "Valid Accounts"
    tactic: str          # e.g. "Persistence"
    description: str = ""


# ---------------------------------------------------------------------------
# Risk score / explanation
# ---------------------------------------------------------------------------

class RiskScoreExplanation(BaseModel):
    """
    Breakdown of how the 0–100 risk score was calculated.
    Each field is the contribution (0–100) from that factor.
    """
    severity_contribution: float = 0.0
    alert_count_contribution: float = 0.0
    ip_reputation_contribution: float = 0.0
    mitre_coverage_contribution: float = 0.0
    false_positive_penalty: float = 0.0
    final_score: float = 0.0


# ---------------------------------------------------------------------------
# Incident models
# ---------------------------------------------------------------------------

class IncidentBase(BaseModel):
    """Fields shared by all incident representations."""
    title: str
    status: str = "open"               # open | investigating | closed
    is_false_positive: bool = False


class IncidentCreate(IncidentBase):
    """Used when creating a new incident programmatically."""
    pass


class Incident(IncidentBase):
    """Full incident as returned from the database."""
    id: int
    risk_score: float = 0.0
    score_explanation: Optional[RiskScoreExplanation] = None
    mitre_techniques: List[MITRETechnique] = []
    bluf_summary: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    alerts: List[Alert] = []           # populated when fetching incident detail

    class Config:
        from_attributes = True
