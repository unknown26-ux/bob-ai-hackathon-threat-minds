/* ThreatLens SOC Dashboard — Main Application */
import { useState, useEffect, useCallback } from 'react'
import './index.css'

const API = ''  // empty = same origin (proxied by Vite to :8000)

/* ── Utility helpers ─────────────────────────────────────────────────── */

function priorityClass(p) {
  if (!p) return 'badge-low'
  const s = p.toUpperCase()
  if (s === 'CRITICAL') return 'badge-critical'
  if (s === 'HIGH')     return 'badge-high'
  if (s === 'MEDIUM')   return 'badge-medium'
  return 'badge-low'
}

function riskBar(score) {
  const pct = Math.min(100, Math.max(0, score))
  let color = '#22c55e'
  if (pct >= 90) color = '#ef4444'
  else if (pct >= 70) color = '#f97316'
  else if (pct >= 40) color = '#eab308'
  return (
    <div className="risk-bar-track">
      <div className="risk-bar-fill" style={{ width: `${pct}%`, background: color }} />
      <span className="risk-bar-label">{pct}</span>
    </div>
  )
}

/* ── Stat Card ───────────────────────────────────────────────────────── */
function StatCard({ label, value, accent }) {
  return (
    <div className={`stat-card ${accent || ''}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}

/* ── MITRE Tags ──────────────────────────────────────────────────────── */
function MitreTags({ techniques }) {
  if (!techniques || techniques.length === 0) return <span className="muted">—</span>
  return (
    <div className="mitre-tags">
      {techniques.map(t => (
        <span key={t.technique_id} className="mitre-tag" title={`${t.name} — ${t.tactic}`}>
          {t.technique_id}
        </span>
      ))}
    </div>
  )
}

/* ── Incident Detail Panel ───────────────────────────────────────────── */
function IncidentDetail({ incidentId, onClose }) {
  const [inc, setInc] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    setLoading(true)
    setError(null)
    fetch(`${API}/api/incidents/${incidentId}`)
      .then(r => { if (!r.ok) throw new Error(r.statusText); return r.json() })
      .then(data => { setInc(data); setLoading(false) })
      .catch(e => { setError(e.message); setLoading(false) })
  }, [incidentId])

  if (loading) return <div className="detail-panel"><div className="loading">Loading…</div></div>
  if (error)   return <div className="detail-panel"><div className="error">Error: {error}</div></div>
  if (!inc)    return null

  const expl = inc.score_explanation || {}
  const alerts = inc.alerts || []
  const techniques = inc.mitre_techniques || []

  return (
    <div className="detail-panel">
      <div className="detail-header">
        <div>
          <span className={`badge ${priorityClass(inc.priority)}`}>{inc.priority}</span>
          <span className="detail-title">{inc.title}</span>
        </div>
        <button className="btn-close" onClick={onClose}>✕ Close</button>
      </div>

      {/* Risk + Confidence row */}
      <div className="detail-meta">
        <div className="meta-block">
          <span className="meta-label">Risk Score</span>
          {riskBar(inc.risk_score)}
        </div>
        <div className="meta-block">
          <span className="meta-label">Confidence</span>
          <span className="meta-value">{inc.confidence}%</span>
        </div>
        <div className="meta-block">
          <span className="meta-label">Status</span>
          <span className="meta-value">{inc.status}</span>
        </div>
        <div className="meta-block">
          <span className="meta-label">False Positive</span>
          <span className="meta-value">{inc.is_false_positive ? '⚠ Likely FP' : 'No'}</span>
        </div>
      </div>

      {/* BLUF */}
      {inc.bluf_summary && (
        <div className="bluf-box">
          <div className="bluf-label">🔴 BLUF — Commander Summary</div>
          <div className="bluf-text">{inc.bluf_summary}</div>
        </div>
      )}

      {/* MITRE */}
      <div className="section">
        <div className="section-title">MITRE ATT&CK Techniques</div>
        {techniques.length === 0
          ? <span className="muted">None identified</span>
          : <div className="mitre-detail-list">
              {techniques.map(t => (
                <div key={t.technique_id} className="mitre-item">
                  <span className="mitre-id">{t.technique_id}</span>
                  <span className="mitre-name">{t.name}</span>
                  <span className="mitre-tactic">{t.tactic}</span>
                  <span className="mitre-desc">{t.description}</span>
                </div>
              ))}
            </div>
        }
      </div>

      {/* Risk Explanation */}
      <div className="section">
        <div className="section-title">Risk Score Breakdown</div>
        <div className="explanation-grid">
          {[
            ['Severity',      expl.severity_score,     40],
            ['Alert Volume',  expl.volume_score,        20],
            ['Threat Intel',  expl.threat_intel_score,  25],
            ['MITRE Coverage',expl.mitre_score,         10],
            ['FP Penalty',    -(expl.fp_penalty || 0),  0],
          ].map(([label, val, max]) => (
            <div key={label} className="expl-row">
              <span className="expl-label">{label}</span>
              <span className={`expl-val ${val < 0 ? 'neg' : ''}`}>
                {val != null ? `${val > 0 ? '+' : ''}${val}` : '?'}
                {max > 0 ? ` / ${max}` : ''}
              </span>
            </div>
          ))}
          <div className="expl-row total">
            <span className="expl-label">TOTAL</span>
            <span className="expl-val">{inc.risk_score} / 100</span>
          </div>
        </div>
        {expl.threat_intel_match &&
          <div className="ti-badge">⚡ Threat Intelligence Match</div>}
      </div>

      {/* Correlated Alerts */}
      <div className="section">
        <div className="section-title">Correlated Alerts ({alerts.length})</div>
        <div className="alert-table-wrap">
          <table className="alert-table">
            <thead>
              <tr>
                <th>Time</th><th>Source</th><th>Src IP</th><th>Dst IP</th>
                <th>Event Type</th><th>Sev</th><th>Conf</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map(a => (
                <tr key={a.id}>
                  <td className="ts">{a.timestamp ? a.timestamp.replace('T',' ').slice(0,19) : '—'}</td>
                  <td>{a.source}</td>
                  <td className="ip">{a.src_ip || '—'}</td>
                  <td className="ip">{a.dst_ip || '—'}</td>
                  <td>{a.event_type}</td>
                  <td><span className={`sev sev-${a.severity}`}>{a.severity}</span></td>
                  <td>{a.confidence}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {alerts.length > 0 && (
          <div className="evidence-section">
            <div className="section-title">Evidence Log</div>
            {alerts.map(a => (
              <div key={a.id} className="evidence-item">
                <span className={`sev sev-${a.severity}`}>{a.severity.toUpperCase()}</span>
                <span className="evidence-msg">{a.raw_message}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

/* ── Incident Table Row ──────────────────────────────────────────────── */
function IncidentRow({ inc, onClick, selected }) {
  return (
    <tr
      className={`inc-row ${selected ? 'inc-row-selected' : ''}`}
      onClick={() => onClick(inc.id)}
    >
      <td className="inc-id">INC-{inc.id}</td>
      <td className="inc-title">{inc.title}</td>
      <td>{riskBar(inc.risk_score)}</td>
      <td><span className={`badge ${priorityClass(inc.priority)}`}>{inc.priority}</span></td>
      <td>{inc.confidence}%</td>
      <td><span className="status-dot">{inc.status}</span></td>
      <td><MitreTags techniques={inc.mitre_techniques} /></td>
    </tr>
  )
}

/* ── Main App ────────────────────────────────────────────────────────── */
export default function App() {
  const [incidents, setIncidents] = useState([])
  const [alerts, setAlerts]       = useState([])
  const [selected, setSelected]   = useState(null)
  const [loading, setLoading]     = useState(false)
  const [seeding, setSeeding]     = useState(false)
  const [seedMsg, setSeedMsg]     = useState(null)
  const [lastUpdate, setLastUpdate] = useState(null)

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const [iRes, aRes] = await Promise.all([
        fetch(`${API}/api/incidents`),
        fetch(`${API}/api/alerts`),
      ])
      setIncidents(await iRes.json())
      setAlerts(await aRes.json())
      setLastUpdate(new Date().toLocaleTimeString())
    } catch (e) {
      console.error('Load failed:', e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadData() }, [loadData])

  async function seedData() {
    setSeeding(true)
    setSeedMsg(null)
    try {
      const r = await fetch(`${API}/api/demo/seed`, { method: 'POST' })
      const data = await r.json()
      setSeedMsg(`✓ Seeded ${data.alerts} alerts → ${data.incidents} incidents`)
      await loadData()
    } catch (e) {
      setSeedMsg('✗ Seed failed: ' + e.message)
    } finally {
      setSeeding(false)
    }
  }

  // Derived stats
  const critical = incidents.filter(i => i.priority === 'CRITICAL').length
  const high     = incidents.filter(i => i.priority === 'HIGH').length
  const genuine  = incidents.filter(i => !i.is_false_positive).length

  return (
    <div className="app">
      {/* ── Header ── */}
      <header className="header">
        <div className="header-left">
          <div className="logo">🔍 ThreatLens</div>
          <div className="logo-sub">Threat Intelligence Correlation &amp; Alert Prioritisation</div>
        </div>
        <div className="header-right">
          {lastUpdate && <span className="last-update">Last update: {lastUpdate}</span>}
          <button className="btn btn-seed" onClick={seedData} disabled={seeding}>
            {seeding ? '⏳ Loading…' : '⚡ Load Demo Data'}
          </button>
          <button className="btn btn-refresh" onClick={loadData} disabled={loading}>
            {loading ? '⏳' : '↺ Refresh'}
          </button>
        </div>
      </header>

      {seedMsg && (
        <div className={`seed-msg ${seedMsg.startsWith('✓') ? 'seed-ok' : 'seed-err'}`}>
          {seedMsg}
        </div>
      )}

      <main className="main">
        {/* ── Stat Cards ── */}
        <div className="stats-row">
          <StatCard label="Total Alerts"    value={alerts.length}     accent="card-blue" />
          <StatCard label="Total Incidents" value={incidents.length}   accent="card-blue" />
          <StatCard label="Critical"        value={critical}           accent="card-critical" />
          <StatCard label="High Risk"       value={high}               accent="card-high" />
          <StatCard label="Genuine Threats" value={genuine}            accent="card-medium" />
        </div>

        {/* ── Incident Table ── */}
        <div className="panel">
          <div className="panel-header">
            <span>Incidents — sorted by risk ↓</span>
            <span className="muted">{incidents.length} total</span>
          </div>
          {incidents.length === 0
            ? (
              <div className="empty-state">
                <p>No incidents yet.</p>
                <p>Click <strong>⚡ Load Demo Data</strong> to run the full ThreatLens pipeline.</p>
              </div>
            )
            : (
              <div className="table-wrap">
                <table className="inc-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Title</th>
                      <th>Risk</th>
                      <th>Priority</th>
                      <th>Confidence</th>
                      <th>Status</th>
                      <th>MITRE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {incidents.map(inc => (
                      <IncidentRow
                        key={inc.id}
                        inc={inc}
                        selected={selected === inc.id}
                        onClick={id => setSelected(id === selected ? null : id)}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            )
          }
        </div>

        {/* ── Incident Detail ── */}
        {selected && (
          <IncidentDetail
            incidentId={selected}
            onClose={() => setSelected(null)}
          />
        )}
      </main>

      <footer className="footer">
        ThreatLens — Threat Minds | IBM Bob AI Innovation Hackathon 2026
      </footer>
    </div>
  )
}
