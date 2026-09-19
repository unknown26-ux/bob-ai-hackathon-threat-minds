"""
api/generators.py — Generator Hub API endpoints

GET  /api/generators                               — list generators
GET  /api/generators/{incident_id}/context        — incident context snapshot
POST /api/generators/{incident_id}/threat-intelligence
POST /api/generators/{incident_id}/attack-scenario
POST /api/generators/{incident_id}/iocs
POST /api/generators/{incident_id}/mitre-chain
POST /api/generators/{incident_id}/threat-report
POST /api/generators/{incident_id}/detection-rule
POST /api/generators/{incident_id}/response-playbook
POST /api/generators/{incident_id}/threat-hunting
POST /api/generators/{incident_id}/executive-brief
POST /api/generators/{incident_id}/attack-simulation
POST /api/generators/{incident_id}/full-package
"""

from fastapi import APIRouter, HTTPException
from generators.context import load_context
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
    generate_full_package,
)

router = APIRouter(prefix="/api/generators")

GENERATOR_CATALOG = [
    {"id": "threat-intelligence", "name": "Threat Intelligence",     "icon": "⚡", "description": "Structured intelligence report: overview, observed behaviour, objectives, evidence gaps, investigation guidance."},
    {"id": "attack-scenario",     "name": "Attack Scenario",          "icon": "🧩", "description": "ATT&CK kill-chain reconstruction showing which tactic stages were observed."},
    {"id": "iocs",                "name": "IOC Extractor",            "icon": "🔎", "description": "Extract real indicators (IPs, usernames, processes) from alert evidence."},
    {"id": "mitre-chain",         "name": "MITRE ATT&CK Chain",       "icon": "🎯", "description": "Ordered technique chain derived from correlated alert evidence."},
    {"id": "threat-report",       "name": "Threat Report",            "icon": "📄", "description": "Full analyst report: executive summary, timeline, assets, MITRE, recommendations."},
    {"id": "detection-rule",      "name": "Detection Rule",           "icon": "🛡",  "description": "Sigma / KQL detection logic derived from observed attack patterns."},
    {"id": "response-playbook",   "name": "Response Playbook",        "icon": "🚨", "description": "Phased SOC response: triage → containment → investigation → eradication → recovery."},
    {"id": "threat-hunting",      "name": "Threat Hunting Queries",   "icon": "🔭", "description": "KQL / SPL / SQL hunting queries targeting observed attacker IPs and TTPs."},
    {"id": "executive-brief",     "name": "Executive Brief",          "icon": "👔", "description": "150-200 word non-technical management summary with recommended executive action."},
    {"id": "attack-simulation",   "name": "Safe Attack Simulation",   "icon": "🧪", "description": "Defensive-only simulation scenarios for validating detection capabilities."},
]


async def _get_ctx(incident_id: int):
    ctx = await load_context(incident_id)
    if ctx is None:
        raise HTTPException(404, f"Incident {incident_id} not found")
    return ctx


@router.get("")
async def list_generators():
    return GENERATOR_CATALOG


@router.get("/{incident_id}/context")
async def get_context(incident_id: int):
    ctx = await _get_ctx(incident_id)
    return ctx.to_dict()


@router.post("/{incident_id}/threat-intelligence")
async def gen_threat_intelligence(incident_id: int):
    return generate_threat_intelligence(await _get_ctx(incident_id))


@router.post("/{incident_id}/attack-scenario")
async def gen_attack_scenario(incident_id: int):
    return generate_attack_scenario(await _get_ctx(incident_id))


@router.post("/{incident_id}/iocs")
async def gen_iocs(incident_id: int):
    return generate_iocs(await _get_ctx(incident_id))


@router.post("/{incident_id}/mitre-chain")
async def gen_mitre_chain(incident_id: int):
    return generate_mitre_chain(await _get_ctx(incident_id))


@router.post("/{incident_id}/threat-report")
async def gen_threat_report(incident_id: int):
    return generate_threat_report(await _get_ctx(incident_id))


@router.post("/{incident_id}/detection-rule")
async def gen_detection_rule(incident_id: int):
    return generate_detection_rule(await _get_ctx(incident_id))


@router.post("/{incident_id}/response-playbook")
async def gen_response_playbook(incident_id: int):
    return generate_response_playbook(await _get_ctx(incident_id))


@router.post("/{incident_id}/threat-hunting")
async def gen_threat_hunting(incident_id: int):
    return generate_threat_hunting(await _get_ctx(incident_id))


@router.post("/{incident_id}/executive-brief")
async def gen_executive_brief(incident_id: int):
    return generate_executive_brief(await _get_ctx(incident_id))


@router.post("/{incident_id}/attack-simulation")
async def gen_attack_simulation(incident_id: int):
    return generate_attack_simulation(await _get_ctx(incident_id))


@router.post("/{incident_id}/full-package")
async def gen_full_package(incident_id: int):
    return generate_full_package(await _get_ctx(incident_id))
