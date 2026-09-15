# ThreatLens — Source Code

## Structure

```
src/
├── backend/          ← FastAPI backend (Python)
│   ├── main.py           ← FastAPI app entry point
│   ├── database.py       ← SQLite async setup
│   ├── models.py         ← Pydantic data models
│   ├── demo_data.py      ← 25 realistic demo alerts
│   ├── normalizer.py     ← Multi-format alert normalizer
│   ├── correlator.py     ← Union-find correlation engine
│   ├── mitre_mapper.py   ← MITRE ATT&CK keyword mapper
│   ├── scorer.py         ← 0-100 risk scorer + FP classifier
│   ├── bluf_generator.py ← Commander BLUF template engine
│   ├── requirements.txt  ← Python dependencies
│   └── api/
│       ├── health.py     ← GET /api/health
│       ├── incidents.py  ← GET /api/incidents, GET /api/incidents/{id}
│       ├── alerts.py     ← GET /api/alerts
│       └── demo.py       ← POST /api/demo/seed
│
├── mcp_server/       ← IBM Bob MCP server (Python)
│   └── server.py         ← 5 MCP tools over stdio transport
│
└── frontend/         ← React + Vite dashboard (JavaScript)
    ├── src/
    │   ├── App.jsx       ← Full SOC dashboard application
    │   └── index.css     ← Dark SOC theme styles
    └── package.json
```

## Quick Start

```cmd
:: Backend
cd src\backend
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

:: Frontend (new terminal)
cd src\frontend
npm install && npm run dev
```

Then open `http://localhost:5173` and click **⚡ Load Demo Data**.
