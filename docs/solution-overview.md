# Solution Overview

## What We Built

ThreatLens is a local threat intelligence correlation and alert prioritisation assistant. It ingests raw security alerts from multiple simulated sources, normalises them to a common schema, groups related alerts into incidents using a deterministic correlation engine, scores each incident with an explainable 0–100 risk score, maps attacker behaviour to MITRE ATT&CK techniques, and generates commander-level BLUF summaries. A React dashboard provides the analyst interface. IBM Bob connects via an MCP server to answer natural-language queries about live incidents.

## How It Works

1. **Ingest**: Raw alerts from three source types (SIEM/auth, Firewall/network, ThreatIntel) are submitted to `POST /api/demo/seed`
2. **Normalise**: The normalizer (`normalizer.py`) maps each raw alert to a common 8-field schema: `{timestamp, source, src_ip, dst_ip, event_type, severity, confidence, indicator}`
3. **Correlate**: The correlation engine (`correlator.py`) applies union-find grouping — alerts sharing the same `src_ip` within 10 minutes, or the same `indicator` at any time, are merged into one incident group
4. **Score**: The scorer (`scorer.py`) calculates a 0–100 risk score from five transparent factors: severity (0–40), alert volume (0–20), threat-intel match (0–25), MITRE coverage (0–10), FP penalty (–30). Confidence is the average of individual alert confidences, boosted for TI matches
5. **Map**: The MITRE mapper (`mitre_mapper.py`) scans alert event types and message text against a keyword table and returns matching ATT&CK technique structs
6. **BLUF**: The BLUF generator (`bluf_generator.py`) assembles a structured commander summary from the scored incident data using a deterministic template
7. **Persist**: All incidents and alerts are stored in SQLite via aiosqlite
8. **Serve**: FastAPI exposes the data via REST endpoints consumed by the React dashboard and MCP server
9. **Bob**: IBM Bob connects to the MCP server via stdio and can call any of five tools to query the live database

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Union-find for correlation | Efficiently handles transitive grouping: if A relates to B and B relates to C, all three merge into one incident |
| Deterministic scoring, no ML | Judges and analysts can see exactly why a score is what it is — trust requires transparency |
| SQLite not PostgreSQL | Zero-config, zero-install, perfect for a local MVP that judges can run in seconds |
| Template BLUF, not LLM | Works offline, deterministic, and produces consistent structured output every time |
| MCP stdio transport | Matches Bob's native integration model; no HTTP server needed for the MCP layer |
| Single-file CSS | Keeps the frontend deployable with `npm run build` without any CSS-in-JS or Tailwind setup overhead |

## IBM Technologies Used

- **IBM Bob (MCP integration):** The MCP server (`src/mcp_server/server.py`) registers five tools with Bob: `get_priority_incidents`, `get_incident`, `investigate_incident`, `get_mitre_mapping`, `generate_bluf`. Bob calls these during analyst sessions to retrieve live ThreatLens data and present it in natural language. The integration is structural — Bob cannot answer incident questions without the MCP server running.

## What Makes It Different

Most alert triage tools either require expensive infrastructure or operate as black boxes. ThreatLens shows its working: every risk score includes a breakdown showing each factor's contribution, every incident shows the full alert timeline, and every BLUF explains what was observed and why the risk level was assigned. An analyst can audit any automated decision in seconds.
