/* ThreatLens SOC Dashboard — Main Application v3
   High-volume live log ingestion + backend-generated intelligence */
import { useState, useEffect, useCallback, useRef } from 'react'
import './index.css'

const API = ''  // proxied by Vite to :8000

/* ════════════════════════════════════════════════════════════
   Utility helpers
════════════════════════════════════════════════════════════ */

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

function fmt(n) {
  if (n == null) return '—'
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M'
  if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'K'
  return String(n)
}

/* ════════════════════════════════════════════════════════════
   Stat Card
════════════════════════════════════════════════════════════ */
function StatCard({ label, value, accent, sub }) {
  return (
    <div className={`stat-card ${accent || ''}`}>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
      <div className="stat-label">{label}</div>
    </div>
  )
}

/* ════════════════════════════════════════════════════════════
   MITRE Tags
════════════════════════════════════════════════════════════ */
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

/* ════════════════════════════════════════════════════════════
   Incident Detail Panel
════════════════════════════════════════════════════════════ */
function IncidentDetail({ incidentId, onClose }) {
  const [inc, setInc] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [alertPage, setAlertPage] = useState(0)
  const PAGE_SIZE = 50

  const loadIncident = useCallback(async () => {
    setLoading(true)
    try {
      const r = await fetch(`${API}/api/incidents/${incidentId}?_=${Date.now()}`, { cache: 'no-store' })
      if (!r.ok) throw new Error(r.statusText)
      setInc(await r.json())
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [incidentId])

  useEffect(() => {
    setAlertPage(0)
    loadIncident()
  }, [loadIncident])

  useEffect(() => {
    if (!incidentId) return
    const id = setInterval(() => {
      loadIncident()
    }, 10000)
    return () => clearInterval(id)
  }, [incidentId, loadIncident])

  if (loading) return <div className="detail-panel"><div className="loading">Loading…</div></div>
  if (error)   return <div className="detail-panel"><div className="error">Error: {error}</div></div>
  if (!inc)    return null

  const expl       = inc.score_explanation || {}
  const fp         = inc.false_positive || expl.false_positive || null
  const allAlerts  = inc.alerts || []
  const techniques = inc.mitre_techniques || []
  const pageAlerts = allAlerts.slice(alertPage * PAGE_SIZE, (alertPage + 1) * PAGE_SIZE)
  const totalPages = Math.ceil(allAlerts.length / PAGE_SIZE)

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
        <div className="meta-block">
          <span className="meta-label">Total Events</span>
          <span className="meta-value">{allAlerts.length.toLocaleString()}</span>
        </div>
      </div>

      {/* BLUF */}
      {inc.bluf_summary && (
        <div className="bluf-box">
          <div className="bluf-label">🔴 BLUF — Commander Summary</div>
          <div className="bluf-text">{inc.bluf_summary}</div>
        </div>
      )}

      {/* False Positive Analysis */}
      {fp && (
        <div className="section">
          <div className="section-title">False Positive Analysis</div>
          <div className="fp-card">
            <div className="fp-header-row">
              <div>
                <div className="meta-label">FP Score</div>
                <div className="fp-score">{fp.percentage ?? fp.score ?? 0}%</div>
              </div>
              <div className="fp-likelihood-wrap">
                <span className="meta-label">FP Likelihood</span>
                <span className={`fp-likelihood fp-${String(fp.likelihood || 'Low').toLowerCase()}`}>
                  {fp.likelihood || 'Low'}
                </span>
              </div>
            </div>
            <div className="fp-reason">{fp.reason || 'No explanation available.'}</div>
            <div className="fp-note">{fp.measurement || 'Estimated false-positive likelihood (not a measured FPR)'}</div>
            {fp.factors && fp.factors.length > 0 && (
              <div className="fp-factors">
                <div className="meta-label">Factors</div>
                <ul>
                  {fp.factors.map((factor, idx) => <li key={`${factor}-${idx}`}>{factor}</li>)}
                </ul>
              </div>
            )}
          </div>
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
            ['Severity',       expl.severity_score,      40],
            ['Alert Volume',   expl.volume_score,         20],
            ['Threat Intel',   expl.threat_intel_score,   25],
            ['MITRE Coverage', expl.mitre_score,          10],
            ['FP Penalty',     -(expl.fp_penalty || 0),    0],
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

      {/* ── Intelligence sections (generated by backend pipeline) ── */}
      <IntelligencePanel intel={inc.intelligence} />

      {/* Correlated Alerts — paginated */}
      <div className="section">
        <div className="section-title-row">
          <span className="section-title">Correlated Alerts ({allAlerts.length.toLocaleString()})</span>
          {totalPages > 1 && (
            <div className="pagination">
              <button className="pg-btn" disabled={alertPage === 0} onClick={() => setAlertPage(p => p - 1)}>‹ Prev</button>
              <span className="pg-info">Page {alertPage + 1} / {totalPages}</span>
              <button className="pg-btn" disabled={alertPage >= totalPages - 1} onClick={() => setAlertPage(p => p + 1)}>Next ›</button>
            </div>
          )}
        </div>
        <div className="alert-table-wrap">
          <table className="alert-table">
            <thead>
              <tr>
                <th>Time</th><th>Source</th><th>Src IP</th><th>Dst IP</th>
                <th>Event Type</th><th>Sev</th><th>Conf</th>
              </tr>
            </thead>
            <tbody>
              {pageAlerts.map(a => (
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
      </div>
    </div>
  )
}

/* ════════════════════════════════════════════════════════════
   Incident Table Row
════════════════════════════════════════════════════════════ */
function IncidentRow({ inc, onClick, selected }) {
  return (
    <tr className={`inc-row ${selected ? 'inc-row-selected' : ''}`} onClick={() => onClick(inc.id)}>
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

/* ════════════════════════════════════════════════════════════
   Live Log Monitor — real-time ingestion metrics
════════════════════════════════════════════════════════════ */
function LiveLogMonitor() {
  const [metrics, setMetrics] = useState(null)
  const [connected, setConnected] = useState(false)
  const esRef = useRef(null)

  useEffect(() => {
    const es = new EventSource(`${API}/api/ingest/stream`)
    esRef.current = es

    es.onopen  = () => setConnected(true)
    es.onerror = () => setConnected(false)
    es.onmessage = (e) => {
      try { setMetrics(JSON.parse(e.data)) } catch {}
    }
    return () => { es.close(); setConnected(false) }
  }, [])

  const m = metrics || {}

  return (
    <div className="panel live-monitor-panel">
      <div className="panel-header">
        <span>⚡ Live Log Monitor</span>
        <span className={`conn-badge ${connected ? 'conn-ok' : 'conn-off'}`}>
          {connected ? '● LIVE' : '○ Offline'}
        </span>
      </div>

      <div className="monitor-grid">
        <div className="monitor-metric">
          <span className="mm-val accent">{fmt(m.received)}</span>
          <span className="mm-label">Events Received</span>
        </div>
        <div className="monitor-metric">
          <span className="mm-val good">{fmt(m.processed)}</span>
          <span className="mm-label">Events Processed</span>
        </div>
        <div className="monitor-metric">
          <span className="mm-val">{fmt(m.pending)}</span>
          <span className="mm-label">Pending</span>
        </div>
        <div className="monitor-metric">
          <span className="mm-val accent">{m.events_per_sec ?? '—'}</span>
          <span className="mm-label">Events / sec</span>
        </div>
        <div className="monitor-metric">
          <span className="mm-val">{m.latency_ms != null ? `${m.latency_ms} ms` : '—'}</span>
          <span className="mm-label">Proc Latency</span>
        </div>
        <div className="monitor-metric">
          <span className="mm-val warn">{fmt(m.suspicious)}</span>
          <span className="mm-label">Suspicious Events</span>
        </div>
        <div className="monitor-metric">
          <span className="mm-val critical">{fmt(m.critical_events)}</span>
          <span className="mm-label">Critical Events</span>
        </div>
        <div className="monitor-metric">
          <span className="mm-val">{fmt(m.incidents_created)}</span>
          <span className="mm-label">Incidents Created</span>
        </div>
        <div className="monitor-metric">
          <span className="mm-val">{fmt(m.incidents_updated)}</span>
          <span className="mm-label">Incidents Updated</span>
        </div>
        <div className="monitor-metric">
          <span className="mm-val">{fmt(m.duplicates)}</span>
          <span className="mm-label">Duplicates</span>
        </div>
        <div className="monitor-metric">
          <span className="mm-val critical">{fmt(m.failed)}</span>
          <span className="mm-label">Failed Events</span>
        </div>
        <div className="monitor-metric">
          <span className="mm-val accent">{fmt(m.unique_source_ips)}</span>
          <span className="mm-label">Unique Source IPs</span>
        </div>
      </div>
    </div>
  )
}

/* ════════════════════════════════════════════════════════════
   Latest Events Stream — windowed, no 5000 DOM elements
════════════════════════════════════════════════════════════ */
const STREAM_WINDOW = 50   // max DOM rows visible

function LatestEvents({ alerts, loading }) {
  const [filter, setFilter] = useState('')
  const [page, setPage]     = useState(0)
  const PAGE_SIZE = 50

  const lower = filter.toLowerCase()
  const filtered = filter
    ? alerts.filter(a =>
        (a.src_ip      || '').includes(filter) ||
        (a.event_type  || '').toLowerCase().includes(lower) ||
        (a.severity    || '').toLowerCase().includes(lower) ||
        (a.raw_message || '').toLowerCase().includes(lower)
      )
    : alerts

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const safeP      = Math.min(page, totalPages - 1)
  const pageRows   = filtered.slice(safeP * PAGE_SIZE, (safeP + 1) * PAGE_SIZE)

  const lastEvent = alerts[0]
  const lastTs    = lastEvent
    ? lastEvent.timestamp?.replace('T', ' ').slice(0, 19)
    : null

  return (
    <div className="panel">
      <div className="panel-header">
        <span>📡 Latest Events (showing {pageRows.length} of {filtered.length.toLocaleString()})</span>
        {lastTs && <span className="muted" style={{ fontSize: 11 }}>Last: {lastTs}</span>}
      </div>
      <div className="events-toolbar">
        <input
          className="filter-input"
          placeholder="Filter by IP, type, severity…"
          value={filter}
          onChange={e => { setFilter(e.target.value); setPage(0) }}
        />
        {totalPages > 1 && (
          <div className="pagination">
            <button className="pg-btn" disabled={safeP === 0} onClick={() => setPage(p => Math.max(0, p - 1))}>‹</button>
            <span className="pg-info">{safeP + 1} / {totalPages}</span>
            <button className="pg-btn" disabled={safeP >= totalPages - 1} onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}>›</button>
          </div>
        )}
      </div>
      {loading && <div className="loading">Loading events…</div>}
      <div className="alert-table-wrap">
        <table className="alert-table events-table">
          <thead>
            <tr>
              <th>Time</th><th>Src IP</th><th>Event Type</th>
              <th>Method</th><th>Severity</th><th>Confidence</th><th>Source</th>
            </tr>
          </thead>
          <tbody>
            {pageRows.map(a => (
              <tr key={a.id} className={`ev-row sev-row-${a.severity}`}>
                <td className="ts">{a.timestamp?.replace('T',' ').slice(0,19) ?? '—'}</td>
                <td className="ip">{a.src_ip || '—'}</td>
                <td className="event-type-cell">{a.event_type}</td>
                <td className="ip">{a.dst_ip || '—'}</td>
                <td><span className={`sev sev-${a.severity}`}>{a.severity}</span></td>
                <td>{a.confidence}%</td>
                <td className="source-cell">{a.source}</td>
              </tr>
            ))}
            {pageRows.length === 0 && (
              <tr><td colSpan={7} className="empty-cell">No events match filter</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/* ════════════════════════════════════════════════════════════
   Load Test Panel
════════════════════════════════════════════════════════════ */
const LOAD_OPTIONS = [100, 500, 1000, 5000, 10000]

function LoadTestPanel({ onTestComplete }) {
  const [count,   setCount]   = useState(1000)
  const [running, setRunning] = useState(false)
  const [status,  setStatus]  = useState(null)
  const [result,  setResult]  = useState(null)
  const [error,   setError]   = useState(null)
  const pollRef = useRef(null)

  const startTest = async () => {
    setRunning(true); setResult(null); setError(null); setStatus(null)
    try {
      const r = await fetch(`${API}/api/loadtest/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ count }),
      })
      if (!r.ok) {
        const err = await r.json()
        throw new Error(err.error || r.statusText)
      }
    } catch (e) {
      setError(e.message); setRunning(false); return
    }

    // Poll status
    pollRef.current = setInterval(async () => {
      try {
        const r   = await fetch(`${API}/api/loadtest/status`)
        const data = await r.json()
        setStatus(data)

        if (data.test?.completed) {
          clearInterval(pollRef.current)
          setRunning(false)
          setResult(data)
          onTestComplete?.()
        }
      } catch {}
    }, 500)
  }

  useEffect(() => () => clearInterval(pollRef.current), [])

  const test    = status?.test    || {}
  const metrics = status?.metrics || {}
  const prog    = test.events_target > 0
    ? Math.round((test.events_sent / test.events_target) * 100)
    : 0

  return (
    <div className="panel loadtest-panel">
      <div className="panel-header">
        <span>🚀 Load Test Simulator</span>
        <span className="muted" style={{ fontSize: 11 }}>localhost only — no external traffic</span>
      </div>

      <div className="loadtest-body">
        <div className="loadtest-controls">
          <div className="loadtest-label">Select event count:</div>
          <div className="count-buttons">
            {LOAD_OPTIONS.map(n => (
              <button
                key={n}
                className={`count-btn ${count === n ? 'count-btn-active' : ''}`}
                onClick={() => setCount(n)}
                disabled={running}
              >
                {n.toLocaleString()}
              </button>
            ))}
          </div>
          <button
            className="btn btn-loadtest"
            onClick={startTest}
            disabled={running}
          >
            {running ? '⏳ Running…' : '▶ Start Live Load Test'}
          </button>
        </div>

        {/* Progress */}
        {running && (
          <div className="lt-progress-wrap">
            <div className="lt-progress-track">
              <div className="lt-progress-fill" style={{ width: `${prog}%` }} />
            </div>
            <div className="lt-progress-label">
              Sent {test.events_sent?.toLocaleString()} / {test.events_target?.toLocaleString()} events
              {status?.elapsed_sec != null && ` — ${status.elapsed_sec}s`}
            </div>
            <div className="lt-live-metrics">
              <span>Queue: {metrics.pending?.toLocaleString() ?? '—'}</span>
              <span>Processed: {metrics.processed?.toLocaleString() ?? '—'}</span>
              <span>Rate: {metrics.events_per_sec ?? '—'} /s</span>
              <span>Incidents created: {metrics.incidents_created ?? '—'}</span>
            </div>
          </div>
        )}

        {error && <div className="lt-error">✗ {error}</div>}

        {/* Result */}
        {result && !running && (
          <div className="lt-result">
            <div className="lt-result-title">✅ LOAD TEST COMPLETE</div>
            <div className="lt-result-grid">
              {[
                ['Events Sent',        result.test?.events_sent,            ''],
                ['Events Received',    result.metrics?.received,            ''],
                ['Events Processed',   result.metrics?.processed,           ''],
                ['Failed',             result.metrics?.failed,              'bad'],
                ['Duplicates',         result.metrics?.duplicates,          ''],
                ['Suspicious Events',  result.metrics?.suspicious,          'warn'],
                ['Critical Events',    result.metrics?.critical_events,     'crit'],
                ['Incidents Created',  result.metrics?.incidents_created,   ''],
                ['Incidents Updated',  result.metrics?.incidents_updated,   ''],
                ['Avg Rate (eps)',      result.avg_rate_eps,                 ''],
                ['Elapsed (s)',         result.elapsed_sec,                 ''],
              ].map(([label, val, cls]) => (
                <div key={label} className={`lt-res-row ${cls}`}>
                  <span className="lt-res-label">{label}</span>
                  <span className="lt-res-val">{val?.toLocaleString?.() ?? val ?? '—'}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Attacker profiles info */}
        <div className="lt-profiles">
          <div className="lt-profiles-title">Simulated Attacker Profiles</div>
          <table className="lt-profile-table">
            <thead><tr><th>Source IP</th><th>Share</th><th>Profile</th></tr></thead>
            <tbody>
              {[
                ['185.22.14.8',   '35%', 'Brute Force / Auth Failures'],
                ['10.20.5.12',    '25%', 'Port Scan / Admin Probe'],
                ['172.16.4.20',   '20%', 'API Abuse'],
                ['203.0.113.55',  '12%', 'Reconnaissance'],
                ['91.108.56.200', '8%',  'Credential Stuffing'],
              ].map(([ip, share, profile]) => (
                <tr key={ip}>
                  <td className="ip">{ip}</td>
                  <td>{share}</td>
                  <td>{profile}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

/* ════════════════════════════════════════════════════════════
   Intelligence Panel — displays backend-generated intelligence
   stored in inc.intelligence (populated by /api/demo/generate)
════════════════════════════════════════════════════════════ */

function ConfidenceBadge({ level }) {
  const cls = level === 'OBSERVED' ? 'conf-observed' : level === 'INFERRED' ? 'conf-inferred' : 'conf-unknown'
  return <span className={`conf-badge ${cls}`}>{level}</span>
}

function IntelligencePanel({ intel }) {
  if (!intel) return null
  const keys = Object.keys(intel)
  if (keys.length === 0) return null

  return (
    <div className="section intel-section">
      <div className="section-title">🧠 Intelligence Analysis</div>

      {/* Threat Intelligence */}
      {intel['threat-intelligence'] && (() => {
        const d = intel['threat-intelligence']
        return (
          <div className="intel-block">
            <div className="intel-block-title">⚡ Threat Intelligence</div>
            {d.threat_overview && <p className="gen-prose">{d.threat_overview}</p>}
            {d.observed_behaviour?.length > 0 && (
              <div className="intel-sub">
                <div className="intel-sub-title">Observed Behaviour</div>
                {d.observed_behaviour.map((b, i) => <div key={i} className="gen-bullet">{b}</div>)}
              </div>
            )}
            {d.risk_interpretation && <p className="gen-note">{d.risk_interpretation}</p>}
          </div>
        )
      })()}

      {/* IOC Analysis */}
      {intel['iocs'] && (() => {
        const d = intel['iocs']
        return (
          <div className="intel-block">
            <div className="intel-block-title">🔎 IOC Analysis ({d.total_iocs} indicators)</div>
            {d.iocs?.length > 0 && (
              <div className="alert-table-wrap">
                <table className="alert-table">
                  <thead><tr><th>Value</th><th>Type</th><th>Event</th><th>Conf</th><th>TI</th></tr></thead>
                  <tbody>
                    {d.iocs.slice(0, 10).map((ioc, i) => (
                      <tr key={i}>
                        <td className="ip">{ioc.value}</td>
                        <td>{ioc.type}</td>
                        <td>{ioc.source_alert_event}</td>
                        <td><ConfidenceBadge level={ioc.confidence} /></td>
                        <td>{ioc.threat_intel ? '⚡' : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )
      })()}

      {/* Detection Rules */}
      {intel['detection-rule'] && (() => {
        const d = intel['detection-rule']
        return (
          <div className="intel-block">
            <div className="intel-block-title">🛡 Detection Rules</div>
            {d.rules?.map((rule, i) => (
              <div key={i} className="gen-section">
                <div className="gen-section-title">{rule.name}</div>
                <div className="gen-meta-row">
                  <span className="muted">{rule.mitre}</span>
                  <span className={`badge ${priorityClass(rule.severity)}`}>{rule.severity}</span>
                </div>
                <div className="gen-subsection-title">Sigma</div>
                <pre className="gen-code">{rule.sigma_rule}</pre>
              </div>
            ))}
          </div>
        )
      })()}

      {/* Response Playbook */}
      {intel['response-playbook'] && (() => {
        const d = intel['response-playbook']
        return (
          <div className="intel-block">
            <div className="intel-block-title">🚨 Response Playbook</div>
            {d.playbook_steps?.map((step, i) => (
              <div key={i} className="playbook-step gen-section">
                <div className="playbook-phase">
                  <span className="playbook-num">{i + 1}</span>
                  <span className="playbook-name">{step.phase}</span>
                  <span className={`badge ${priorityClass(step.priority)}`}>{step.priority}</span>
                </div>
                {step.actions?.map((a, j) => <div key={j} className="gen-bullet">→ {a}</div>)}
                <div className="gen-note">Expected: {step.expected_result}</div>
              </div>
            ))}
          </div>
        )
      })()}

      {/* Threat Hunting */}
      {intel['threat-hunting'] && (() => {
        const d = intel['threat-hunting']
        return (
          <div className="intel-block">
            <div className="intel-block-title">🔭 Threat Hunting Queries</div>
            {d.queries?.slice(0, 3).map((q, i) => (
              <div key={i} className="gen-section">
                <div className="gen-section-title">{q.objective}</div>
                <div className="gen-subsection-title">KQL</div>
                <pre className="gen-code">{q.kql}</pre>
              </div>
            ))}
          </div>
        )
      })()}

      {/* Executive Brief */}
      {intel['executive-brief'] && (() => {
        const d = intel['executive-brief']
        return (
          <div className="intel-block">
            <div className="intel-block-title">👔 Executive Brief</div>
            <div className="exec-brief-box">
              <div className="exec-brief-label">{d.title}</div>
              <div className="exec-brief-body">{d.brief}</div>
            </div>
            {d.recommended_action && (
              <div className="intel-sub">
                <div className="intel-sub-title">Recommended Action</div>
                <p className="gen-prose">{d.recommended_action}</p>
              </div>
            )}
          </div>
        )
      })()}

      {/* Attack Scenario */}
      {intel['attack-scenario'] && (() => {
        const d = intel['attack-scenario']
        return (
          <div className="intel-block">
            <div className="intel-block-title">🧩 Attack Scenario</div>
            {d.summary && <p className="gen-prose">{d.summary}</p>}
            {d.stages?.length > 0 && (
              <div className="attack-chain">
                {d.stages.map((s, i) => (
                  <div key={i} className={`chain-stage ${s.observed ? 'chain-observed' : 'chain-not-observed'}`}>
                    <div className="chain-tactic">{s.tactic}</div>
                    <div className="chain-status">{s.observed ? '● OBSERVED' : '○ NOT OBSERVED'}</div>
                    {s.mitre_techniques?.length > 0 && (
                      <div className="chain-techniques">{s.mitre_techniques.join(', ')}</div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )
      })()}
    </div>
  )
}

/* ════════════════════════════════════════════════════════════
   Main App
════════════════════════════════════════════════════════════ */
const TABS = ['incidents', 'live', 'loadtest']
const TAB_LABELS = {
  incidents: '📋 Incidents',
  live:      '⚡ Live Monitor',
  loadtest:  '🚀 Load Test',
}

export default function App() {
  const [tab,         setTab]         = useState('incidents')
  const [incidents,   setIncidents]   = useState([])
  const [alerts,      setAlerts]      = useState([])
  const [stats,       setStats]       = useState(null)
  const [selected,    setSelected]    = useState(null)
  const [loading,     setLoading]     = useState(false)
  const [alertLoad,   setAlertLoad]   = useState(false)
  const [seeding,     setSeeding]     = useState(false)
  const [seedMsg,     setSeedMsg]     = useState(null)
  const [lastUpdate,  setLastUpdate]  = useState(null)
  const [alertLimit,  setAlertLimit]  = useState(200)

  // Polling interval for auto-refresh (faster on live tab)
  const pollMs = tab === 'live' ? 3000 : 10000

  const loadIncidents = useCallback(async () => {
    setLoading(true)
    try {
      const r = await fetch(`${API}/api/incidents?_=${Date.now()}`, { cache: 'no-store' })
      if (!r.ok) throw new Error(r.statusText)
      setIncidents(await r.json())
      setLastUpdate(new Date().toLocaleTimeString())
    } catch (e) {
      console.error('Load incidents failed:', e)
    } finally {
      setLoading(false)
    }
  }, [])

  const loadAlerts = useCallback(async (limit = alertLimit) => {
    setAlertLoad(true)
    try {
      const r = await fetch(`${API}/api/alerts?limit=${limit}&offset=0&_=${Date.now()}`, { cache: 'no-store' })
      if (!r.ok) throw new Error(r.statusText)
      setAlerts(await r.json())
    } catch (e) {
      console.error('Load alerts failed:', e)
    } finally {
      setAlertLoad(false)
    }
  }, [alertLimit])

  // Load stats from backend — single source of truth
  const loadStats = useCallback(async () => {
    try {
      const r = await fetch(`${API}/api/dashboard/stats?_=${Date.now()}`, { cache: 'no-store' })
      if (r.ok) setStats(await r.json())
    } catch {}
  }, [])

  const loadAll = useCallback(async () => {
    await Promise.all([loadIncidents(), loadAlerts(alertLimit), loadStats()])
  }, [loadIncidents, loadAlerts, loadStats, alertLimit])

  // Initial load
  useEffect(() => { loadAll() }, [])

  // Auto-poll
  useEffect(() => {
    const id = setInterval(() => {
      loadIncidents()
      loadStats()
      if (tab === 'live') loadAlerts(alertLimit)
    }, pollMs)
    return () => clearInterval(id)
  }, [pollMs, tab, loadIncidents, loadAlerts, loadStats, alertLimit])

  useEffect(() => {
    if (!selected) return
    const id = setInterval(() => {
      fetch(`${API}/api/incidents/${selected}?_=${Date.now()}`, { cache: 'no-store' })
        .then(r => r.ok ? r.json() : null)
        .then(data => {
          if (!data) return
          setIncidents(current => current.map(item => (item.id === data.id ? data : item)))
        })
        .catch(() => {})
    }, 10000)
    return () => clearInterval(id)
  }, [selected])

  async function seedData() {
    setSeeding(true); setSeedMsg(null)
    try {
      const r    = await fetch(`${API}/api/demo/generate`, { method: 'POST', cache: 'no-store' })
      const data = await r.json()
      const scenarioLabel = data.scenario_name || data.scenario || 'random'
      const genOk = data.generators_ok != null ? ` | ${data.generators_ok}/10 generators` : ''
      setSeedMsg(`✓ ${scenarioLabel}: ${data.alerts} alerts → ${data.incidents} incidents${genOk} [${data.dataset_id}]`)
      await loadAll()
    } catch (e) {
      setSeedMsg('✗ Seed failed: ' + e.message)
    } finally {
      setSeeding(false)
    }
  }

  // Stats come from backend — no client-side calculation
  const critical = stats?.critical ?? incidents.filter(i => i.priority === 'CRITICAL').length
  const high     = stats?.high_risk ?? incidents.filter(i => i.priority === 'HIGH').length
  const genuine  = stats?.genuine_threats ?? incidents.filter(i => !i.is_false_positive).length
  const totalAlerts = stats?.total_alerts ?? alerts.length

  return (
    <div className="app">
      {/* Header */}
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
          <button className="btn btn-refresh" onClick={loadAll} disabled={loading}>
            {loading ? '⏳' : '↺ Refresh'}
          </button>
        </div>
      </header>

      {seedMsg && (
        <div className={`seed-msg ${seedMsg.startsWith('✓') ? 'seed-ok' : 'seed-err'}`}>
          {seedMsg}
        </div>
      )}

      {/* Tab bar */}
      <div className="tab-bar">
        {TABS.map(t => (
          <button
            key={t}
            className={`tab-btn ${tab === t ? 'tab-btn-active' : ''}`}
            onClick={() => setTab(t)}
          >
            {TAB_LABELS[t]}
          </button>
        ))}
      </div>

      <main className="main">
        {/* ── INCIDENTS TAB ── */}
        {tab === 'incidents' && (
          <>
            <div className="stats-row">
              <StatCard label="Total Alerts"    value={totalAlerts.toLocaleString()} accent="card-blue" />
              <StatCard label="Total Incidents" value={stats?.total_incidents ?? incidents.length} accent="card-blue" />
              <StatCard label="Critical"        value={critical}                     accent="card-critical" />
              <StatCard label="High Risk"       value={high}                         accent="card-high" />
              <StatCard label="Genuine Threats" value={genuine}                      accent="card-medium" />
            </div>

            <div className="panel">
              <div className="panel-header">
                <span>Incidents — sorted by risk ↓</span>
                <span className="muted">{incidents.length} total</span>
              </div>
              {incidents.length === 0
                ? (
                  <div className="empty-state">
                    <p>No incidents yet.</p>
                    <p>Click <strong>⚡ Load Demo Data</strong> to run the full ThreatLens pipeline, or use the <strong>Live Monitor</strong> tab to ingest live logs.</p>
                  </div>
                )
                : (
                  <div className="table-wrap">
                    <table className="inc-table">
                      <thead>
                        <tr>
                          <th>ID</th><th>Title</th><th>Risk</th><th>Priority</th>
                          <th>Confidence</th><th>Status</th><th>MITRE</th>
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

            {selected && (
              <IncidentDetail
                incidentId={selected}
                onClose={() => setSelected(null)}
              />
            )}
          </>
        )}

        {/* ── LIVE MONITOR TAB ── */}
        {tab === 'live' && (
          <>
            <LiveLogMonitor />
            <LatestEvents alerts={alerts} loading={alertLoad} />
            <div className="panel" style={{ padding: '12px 16px' }}>
              <div className="panel-header" style={{ borderBottom: 0, padding: 0 }}>
                <span style={{ fontSize: 12, color: 'var(--muted)' }}>
                  Showing latest {alerts.length.toLocaleString()} events —
                </span>
                <div style={{ display: 'flex', gap: 8 }}>
                  {[200, 500, 1000, 5000].map(n => (
                    <button
                      key={n}
                      className={`count-btn ${alertLimit === n ? 'count-btn-active' : ''}`}
                      onClick={() => { setAlertLimit(n); loadAlerts(n) }}
                    >
                      {n.toLocaleString()}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}

        {/* ── LOAD TEST TAB ── */}
        {tab === 'loadtest' && (
          <LoadTestPanel onTestComplete={() => { loadIncidents(); loadAlerts(alertLimit) }} />
        )}

      </main>

      <footer className="footer">
        ThreatLens — Threat Minds | IBM Bob AI Innovation Hackathon 2026
      </footer>
    </div>
  )
}
