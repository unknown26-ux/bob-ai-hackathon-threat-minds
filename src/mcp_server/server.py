"""
mcp_server/server.py — ThreatLens MCP server for IBM Bob integration.

Exposes ThreatLens incident intelligence as MCP tools that Bob can call.
Uses stdio transport — configure in Bob's MCP settings as:
  { "command": "python", "args": ["src/mcp_server/server.py"] }

Tools:
  get_priority_incidents  — list top incidents by risk score
  get_incident            — full detail for one incident
  investigate_incident    — structured investigation summary
  get_mitre_mapping       — MITRE techniques for an incident
  generate_bluf           — BLUF summary for an incident
"""

import json
import sys
import urllib.request
from typing import Any

# MCP SDK — installed via requirements.txt
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

BACKEND_URL = "http://localhost:8000"

app = Server("threatlens")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _get(path: str) -> Any:
    """Call the ThreatLens REST API and return parsed JSON."""
    url = BACKEND_URL + path
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read().decode())


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="get_priority_incidents",
            description=(
                "Returns the highest-priority ThreatLens incidents ordered by risk score. "
                "Use this to answer 'what is the most dangerous incident right now?'"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of incidents to return (default 5)",
                        "default": 5,
                    }
                },
            },
        ),
        Tool(
            name="get_incident",
            description="Returns full details of a specific ThreatLens incident by ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "incident_id": {
                        "type": "integer",
                        "description": "The numeric incident ID",
                    }
                },
                "required": ["incident_id"],
            },
        ),
        Tool(
            name="investigate_incident",
            description=(
                "Returns a structured investigation summary of an incident: "
                "source IPs, targets, event timeline, MITRE techniques, and risk explanation."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "incident_id": {
                        "type": "integer",
                        "description": "The numeric incident ID",
                    }
                },
                "required": ["incident_id"],
            },
        ),
        Tool(
            name="get_mitre_mapping",
            description="Returns the MITRE ATT&CK techniques mapped to a specific incident.",
            inputSchema={
                "type": "object",
                "properties": {
                    "incident_id": {
                        "type": "integer",
                        "description": "The numeric incident ID",
                    }
                },
                "required": ["incident_id"],
            },
        ),
        Tool(
            name="generate_bluf",
            description=(
                "Returns the BLUF (Bottom Line Up Front) commander-level summary "
                "for a specific incident. Use this when asked for a situation report "
                "or commander brief."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "incident_id": {
                        "type": "integer",
                        "description": "The numeric incident ID",
                    }
                },
                "required": ["incident_id"],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Tool call handlers
# ---------------------------------------------------------------------------

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:

    if name == "get_priority_incidents":
        limit = int(arguments.get("limit", 5))
        incidents = _get("/api/incidents")[:limit]
        lines = ["# ThreatLens — Priority Incidents\n"]
        for inc in incidents:
            mitre_ids = ", ".join(
                t.get("technique_id", "") for t in (inc.get("mitre_techniques") or [])
            )
            fp = " [LIKELY FALSE POSITIVE]" if inc.get("is_false_positive") else ""
            lines.append(
                f"**INC-{inc['id']} [{inc['priority']}]** — {inc['title']}\n"
                f"  Risk: {inc['risk_score']}/100 | Confidence: {inc['confidence']}% | "
                f"Status: {inc['status']}{fp}\n"
                f"  MITRE: {mitre_ids or 'none'}\n"
            )
        return [TextContent(type="text", text="\n".join(lines))]

    elif name in ("get_incident", "investigate_incident", "get_mitre_mapping", "generate_bluf"):
        incident_id = int(arguments["incident_id"])
        inc = _get(f"/api/incidents/{incident_id}")

        if name == "get_incident":
            mitre_ids = ", ".join(
                t.get("technique_id", "") for t in (inc.get("mitre_techniques") or [])
            )
            text = (
                f"# Incident INC-{inc['id']}: {inc['title']}\n\n"
                f"**Priority:** {inc['priority']}  \n"
                f"**Risk Score:** {inc['risk_score']}/100  \n"
                f"**Confidence:** {inc['confidence']}%  \n"
                f"**Status:** {inc['status']}  \n"
                f"**False Positive:** {inc['is_false_positive']}  \n"
                f"**MITRE Techniques:** {mitre_ids}  \n\n"
                f"**BLUF:**\n{inc.get('bluf_summary', 'N/A')}\n\n"
                f"**Correlated Alerts:** {len(inc.get('alerts', []))}\n"
            )
            return [TextContent(type="text", text=text)]

        elif name == "investigate_incident":
            alerts = inc.get("alerts", [])
            src_ips  = sorted({a.get("src_ip")  for a in alerts if a.get("src_ip")})
            dst_ips  = sorted({a.get("dst_ip")  for a in alerts if a.get("dst_ip")})
            evt_types = sorted({a.get("event_type") for a in alerts if a.get("event_type")})
            expl = inc.get("score_explanation") or {}

            timeline = "\n".join(
                f"  [{a.get('severity','?').upper()}] {a.get('timestamp','')} "
                f"— {a.get('event_type','')} — {a.get('raw_message','')[:80]}"
                for a in sorted(alerts, key=lambda x: x.get("timestamp", ""))
            )

            text = (
                f"# Investigation: INC-{inc['id']} — {inc['title']}\n\n"
                f"**Source IPs:** {', '.join(src_ips) or 'unknown'}\n"
                f"**Target IPs:** {', '.join(dst_ips) or 'unknown'}\n"
                f"**Event Types:** {', '.join(evt_types)}\n"
                f"**Alert Count:** {len(alerts)}\n\n"
                f"## Risk Breakdown\n"
                f"- Severity Score: {expl.get('severity_score', '?')}/40\n"
                f"- Volume Score: {expl.get('volume_score', '?')}/20\n"
                f"- Threat Intel Score: {expl.get('threat_intel_score', '?')}/25\n"
                f"- MITRE Score: {expl.get('mitre_score', '?')}/10\n"
                f"- FP Penalty: -{expl.get('fp_penalty', 0)}\n"
                f"- **Final Risk: {inc['risk_score']}/100**\n\n"
                f"## Alert Timeline\n{timeline}\n"
            )
            return [TextContent(type="text", text=text)]

        elif name == "get_mitre_mapping":
            techniques = inc.get("mitre_techniques") or []
            lines = [f"# MITRE ATT&CK Techniques — INC-{inc['id']}\n"]
            for t in techniques:
                lines.append(
                    f"**{t['technique_id']}** — {t['name']}  \n"
                    f"  Tactic: {t['tactic']}  \n"
                    f"  {t.get('description', '')}\n"
                )
            if not techniques:
                lines.append("No MITRE techniques mapped for this incident.")
            return [TextContent(type="text", text="\n".join(lines))]

        elif name == "generate_bluf":
            bluf = inc.get("bluf_summary") or "No BLUF available for this incident."
            text = f"# BLUF — INC-{inc['id']}: {inc['title']}\n\n{bluf}"
            return [TextContent(type="text", text=text)]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
