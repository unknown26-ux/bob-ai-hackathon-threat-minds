"""Quick API smoke-test for ThreatLens backend."""
import urllib.request, json, sys

BASE = "http://localhost:8000"

def get(path):
    r = urllib.request.urlopen(BASE + path, timeout=10)
    return json.loads(r.read().decode())

def post(path):
    req = urllib.request.Request(BASE + path, method="POST")
    req.add_header("Content-Length", "0")
    r = urllib.request.urlopen(req, timeout=15)
    return json.loads(r.read().decode())

# Health
h = get("/api/health")
assert h["status"] == "healthy", h
print("HEALTH OK:", h)

# Seed
s = post("/api/demo/seed")
print(f"SEED OK: {s['incidents']} incidents from {s['alerts']} alerts")
for d in s["details"]:
    print(f"  INC-{d['id']}: risk={d['risk_score']} | {d['priority']} | {d['title'][:45]}")

# Alerts
alerts = get("/api/alerts")
print(f"ALERTS OK: {len(alerts)} rows")

# Incidents list
incs = get("/api/incidents")
print(f"INCIDENTS OK: {len(incs)} rows, top risk={incs[0]['risk_score']} {incs[0]['priority']}")

# Incident detail (critical one = highest risk)
top = incs[0]
detail = get(f"/api/incidents/{top['id']}")
print(f"DETAIL OK: id={detail['id']} alerts={len(detail['alerts'])} mitre={len(detail['mitre_techniques'])}")
print(f"  BLUF: {detail['bluf_summary'][:120]}...")

print("\nALL TESTS PASSED")
