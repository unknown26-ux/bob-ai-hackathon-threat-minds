# Setup Guide

> Tested on Windows 10/11 with Python 3.13 and Node.js 18+.

## Prerequisites

- [ ] Python 3.11 or later (`python --version`)
- [ ] Node.js 18 or later (`node --version`)
- [ ] npm 8 or later (`npm --version`)
- [ ] Git (`git --version`)

No Docker, no PostgreSQL, no cloud accounts required.

## Environment Variables

ThreatLens runs without any required environment variables. All defaults work out of the box. For optional customisation:

```cmd
copy src\.env.example src\backend\.env
```

| Variable | Description | Default |
|---|---|---|
| `APP_PORT` | Backend port | `8000` |
| `DATABASE_PATH` | SQLite file path | `threatlens.db` (in `src/backend/`) |

## Backend — Installation & Startup

```cmd
cd src\backend

python -m venv .venv

.venv\Scripts\activate

pip install -r requirements.txt

uvicorn main:app --reload --port 8000
```

The backend will start at `http://localhost:8000`.

Verify it is running:
```cmd
curl http://localhost:8000/api/health
```

Expected response:
```json
{"status": "healthy", "service": "ThreatLens"}
```

## Frontend — Installation & Startup

Open a **second** terminal window:

```cmd
cd src\frontend

npm install

npm run dev
```

The dashboard will be available at `http://localhost:5173`.

## Loading Demo Data

1. Open `http://localhost:5173` in your browser
2. Click **⚡ Load Demo Data**
3. The pipeline runs: 25 alerts → 8 incidents → scored, MITRE-mapped, BLUF-generated
4. The dashboard will show the incident table with the CRITICAL incident at the top

Alternatively, via the API:
```cmd
curl -X POST http://localhost:8000/api/demo/seed
```

## Verifying the Full Pipeline

```cmd
:: Health check
curl http://localhost:8000/api/health

:: Seed demo data
curl -X POST http://localhost:8000/api/demo/seed

:: List all alerts
curl http://localhost:8000/api/alerts

:: List incidents (sorted by risk desc)
curl http://localhost:8000/api/incidents

:: Get critical incident detail (ID 1 after first seed)
curl http://localhost:8000/api/incidents/1
```

## MCP Server (IBM Bob Integration)

With the backend running, configure IBM Bob to use ThreatLens:

Create `.bob/mcp.json` in your workspace root:
```json
{
  "mcpServers": {
    "threatlens": {
      "command": "python",
      "args": ["src/mcp_server/server.py"],
      "cwd": "."
    }
  }
}
```

The MCP server uses the same virtual environment as the backend. Make sure `src\backend\.venv\Scripts\python.exe` is on your PATH, or use the full path:
```json
{
  "mcpServers": {
    "threatlens": {
      "command": "src\\backend\\.venv\\Scripts\\python.exe",
      "args": ["src/mcp_server/server.py"]
    }
  }
}
```

Then in Bob, ask:
- *"What is the most dangerous incident right now?"*
- *"Investigate incident 1"*
- *"Give me a BLUF for the critical incident"*

## Running Backend Tests

```cmd
cd src\backend
.venv\Scripts\python.exe test_api.py
```

Expected output: `ALL TESTS PASSED`

## Frontend Production Build

```cmd
cd src\frontend
npm run build
```

Output: `dist/` directory ready for static hosting.

## Troubleshooting

| Issue | Solution |
|---|---|
| `ModuleNotFoundError` on uvicorn start | Run `pip install -r requirements.txt` in the `src\backend\` directory |
| Port 8000 already in use | Change `--port 8000` to another port (e.g., `8001`) and update the Vite proxy in `vite.config.js` |
| Frontend shows empty incidents | Click **⚡ Load Demo Data** first, or run `POST /api/demo/seed` |
| MCP server times out in Bob | Ensure the backend is running on port 8000 before using Bob MCP tools |
| `pydantic_core` import error | Run `pip install --upgrade pydantic` (Python 3.13 requires pydantic 2.11+) |
| `npm run dev` not found | Run `npm install` in `src\frontend\` first |
