# Demo Screenshots

Place screenshots of the running ThreatLens dashboard in this folder.

## Required Screenshots (minimum 3)

Name them sequentially:

```
01-dashboard-overview.png     ← Full dashboard after loading demo data
02-critical-incident.png      ← Critical incident (INC-1) selected, showing BLUF
03-incident-detail.png        ← Risk breakdown + MITRE techniques + correlated alerts
04-bob-mcp-query.png          ← Optional: IBM Bob MCP query result
```

## How to Capture

1. Start backend: `uvicorn main:app --reload --port 8000` (from `src\backend\`)
2. Start frontend: `npm run dev` (from `src\frontend\`)
3. Open `http://localhost:5173`
4. Click **⚡ Load Demo Data**
5. Screenshot the overview (01)
6. Click INC-1 (CRITICAL incident from 185.22.14.8)
7. Screenshot the full detail panel (02, 03)
