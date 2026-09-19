"""
generators/all_generators.py — All 10 ThreatLens intelligence generators.

Every generator receives an IncidentContext and returns structured output
derived ONLY from the actual incident data. No fabrication.

Evidence confidence labels:
  OBSERVED  — directly in alert data
  INFERRED  — reasoned from patterns in alert data
  UNKNOWN   — not present in evidence, cannot be determined
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from generators.context import IncidentContext

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

KNOWN_MALICIOUS = {"185.22.14.8", "91.108.56.200", "203.0.113.99"}

MITRE_TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]

TACTIC_EVENT_MAP = {
    "port_scan":             "Discovery",
    "authentication_failure": "Credential Access",
    "authentication_success": "Initial Access",
    "privilege_escalation":  "Privilege Escalation",
    "suspicious_script":     "Execution",
    "account_manipulation":  "Persistence",
    "data_exfiltration":     "Exfiltration",
    "data_staged":           "Collection",
    "c2_beaconing":          "Command and Control",
    "threat_intel_match":    "Initial Access",
}


def _conf(level: str) -> str:
    return f"[{level}]"


def _ev_list(ctx: IncidentContext, label: str = "Evidence") -> List[str]:
    return [
        f"{a.get('timestamp','')[:19]}  {a.get('event_type','')}  {a.get('raw_message','')[:120]}"
        for a in ctx.alerts[:20]
    ]


def _severity_label(score: float) -> str:
    if score >= 90: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# 1. Threat Intelligence Generator
# ---------------------------------------------------------------------------

def generate_threat_intelligence(ctx: IncidentContext) -> Dict[str, Any]:
    observed_events = ctx.event_types
    src_str = ", ".join(ctx.source_ips) or "Unknown"
    dst_str = ", ".join(ctx.dest_ips[:3]) or "Internal Assets"

    # Threat overview
    overview_lines = [
        f"Incident '{ctx.title}' (INC-{ctx.incident_id}) has been identified with a risk score of "
        f"{ctx.risk_score}/100 and priority {ctx.priority}.",
        f"The activity originates from {src_str} and targets {dst_str}.",
        f"A total of {ctx.alert_count} correlated alerts have been observed across "
        f"{len(ctx.sources)} telemetry sources.",
    ]
    if ctx.has_threat_intel:
        overview_lines.append(
            f"{_conf('OBSERVED')} One or more source IPs match known threat intelligence feeds."
        )

    # Observed behaviour
    behaviour = []
    for et in observed_events:
        label = et.replace("_", " ").title()
        behaviour.append(f"{_conf('OBSERVED')} {label} activity detected.")

    if ctx.has_threat_intel:
        malicious = [ip for ip in ctx.source_ips if ip in KNOWN_MALICIOUS]
        if malicious:
            behaviour.append(
                f"{_conf('OBSERVED')} Source IP(s) {', '.join(malicious)} confirmed in threat-intel feed."
            )

    # Potential objective (inferred)
    objectives = []
    if "data_exfiltration" in observed_events or "data_staged" in observed_events:
        objectives.append(f"{_conf('INFERRED')} Data theft / exfiltration likely given observed transfer behaviour.")
    if "authentication_failure" in observed_events and "authentication_success" in observed_events:
        objectives.append(f"{_conf('INFERRED')} Credential compromise successful — account takeover likely.")
    if "privilege_escalation" in observed_events:
        objectives.append(f"{_conf('INFERRED')} Privilege escalation observed — attacker may seek persistent admin access.")
    if "c2_beaconing" in observed_events:
        objectives.append(f"{_conf('INFERRED')} Command & Control channel established — persistent access likely goal.")
    if "account_manipulation" in observed_events:
        objectives.append(f"{_conf('INFERRED')} Backdoor account creation suggests persistence as objective.")
    if not objectives:
        objectives.append(f"{_conf('UNKNOWN')} Objective cannot be determined from available telemetry.")

    # Intelligence gaps
    gaps = []
    if not ctx.dest_ips:
        gaps.append(f"{_conf('UNKNOWN')} No destination hosts identified in alert data.")
    if not ctx.has_threat_intel:
        gaps.append(f"{_conf('UNKNOWN')} Source IPs not confirmed in external threat-intel feeds.")
    if "data_exfiltration" not in observed_events:
        gaps.append(f"{_conf('UNKNOWN')} No confirmed data exfiltration observed — impact scope unclear.")
    if not any("success" in e for e in observed_events):
        gaps.append(f"{_conf('UNKNOWN')} No confirmed successful access — attack may still be in early stages.")

    # Recommended investigation
    investigation = [
        f"Review all alerts correlated under INC-{ctx.incident_id} for completeness.",
        f"Verify whether source IP(s) {src_str} have been seen in previous incidents.",
    ]
    if "authentication_success" in observed_events:
        investigation.append("Audit all user sessions initiated from attacker IPs and revoke active sessions.")
    if "privilege_escalation" in observed_events:
        investigation.append("Check for persistence mechanisms: scheduled tasks, new accounts, registry run keys.")
    if "c2_beaconing" in observed_events:
        investigation.append("Capture and analyse DNS traffic from affected hosts. Look for encoded payloads in TXT queries.")
    if "data_exfiltration" in observed_events or "data_staged" in observed_events:
        investigation.append("Identify which data stores were accessible from compromised hosts. Assess data sensitivity.")

    return {
        "generator": "threat_intelligence",
        "incident_id": ctx.incident_id,
        "title":        ctx.title,
        "threat_overview":       " ".join(overview_lines),
        "observed_behaviour":    behaviour,
        "potential_objective":   objectives,
        "mitre_mapping":         ctx.mitre_techniques,
        "risk_interpretation": (
            f"Risk score {ctx.risk_score}/100 ({ctx.priority}). "
            f"Confidence: {ctx.confidence}%. "
            f"{'Threat intel match confirmed.' if ctx.has_threat_intel else 'No external threat-intel match.'} "
            f"{'Likely false positive.' if ctx.is_false_positive else 'Genuine threat indicators present.'}"
        ),
        "evidence":              _ev_list(ctx),
        "intelligence_gaps":     gaps,
        "recommended_investigation": investigation,
        "confidence_note": "Labels: OBSERVED = directly in data. INFERRED = pattern-based reasoning. UNKNOWN = not present.",
    }


# ---------------------------------------------------------------------------
# 2. Attack Scenario Generator
# ---------------------------------------------------------------------------

def generate_attack_scenario(ctx: IncidentContext) -> Dict[str, Any]:
    observed_events = set(ctx.event_types)

    # Build stages based on MITRE tactics, only include observed ones
    tactic_evidence: Dict[str, List] = {}
    for tactic in MITRE_TACTIC_ORDER:
        tactic_evidence[tactic] = []

    # Map event types to tactics
    for alert in ctx.alerts:
        et = alert.get("event_type", "")
        tactic = TACTIC_EVENT_MAP.get(et)
        if tactic:
            tactic_evidence[tactic].append(alert)

    # Also add from MITRE techniques
    for tech in ctx.mitre_techniques:
        tactic = tech.get("tactic", "")
        if tactic in tactic_evidence and not tactic_evidence[tactic]:
            tactic_evidence[tactic].append({"_from_mitre": tech})

    stages = []
    for tactic in MITRE_TACTIC_ORDER:
        evidence = tactic_evidence[tactic]
        if evidence:
            # Find matching MITRE techniques for this tactic
            techs = [t for t in ctx.mitre_techniques if t.get("tactic") == tactic]
            sample_alert = next((e for e in evidence if "event_type" in e), None)
            stages.append({
                "tactic":    tactic,
                "observed":  True,
                "confidence": "OBSERVED",
                "mitre_techniques": [t.get("technique_id") for t in techs],
                "evidence_count":   len(evidence),
                "sample_evidence":  sample_alert.get("raw_message", "")[:150] if sample_alert else "",
            })
        else:
            stages.append({
                "tactic":    tactic,
                "observed":  False,
                "confidence": "NOT OBSERVED",
                "mitre_techniques": [],
                "evidence_count":   0,
                "sample_evidence":  "Not observed in current alert dataset.",
            })

    return {
        "generator":   "attack_scenario",
        "incident_id": ctx.incident_id,
        "title":       ctx.title,
        "summary": (
            f"Attack reconstruction for INC-{ctx.incident_id}. "
            f"Based on {ctx.alert_count} alerts across {len(ctx.sources)} sources. "
            f"Observed {sum(1 for s in stages if s['observed'])} of {len(MITRE_TACTIC_ORDER)} ATT&CK tactic stages."
        ),
        "stages":       stages,
        "primary_actor": ctx.source_ips[0] if ctx.source_ips else "Unknown",
        "targets":       ctx.dest_ips[:5] or ["Internal Assets"],
        "attack_window": {
            "start": ctx.first_seen,
            "end":   ctx.last_seen,
        },
    }


# ---------------------------------------------------------------------------
# 3. IOC Generator
# ---------------------------------------------------------------------------

def generate_iocs(ctx: IncidentContext) -> Dict[str, Any]:
    iocs = []

    # IPs from alerts
    for a in ctx.alerts:
        for field_, ioc_type in [("src_ip", "IP Address"), ("dst_ip", "IP Address"), ("indicator", "Indicator")]:
            val = a.get(field_)
            if val and not val.endswith("/24") and not val.endswith("/8"):  # skip subnets
                existing = next((i for i in iocs if i["value"] == val), None)
                if existing:
                    existing["last_seen"] = max(existing["last_seen"], a.get("timestamp", ""))
                    existing["occurrences"] += 1
                else:
                    iocs.append({
                        "value":       val,
                        "type":        ioc_type,
                        "source_alert_event": a.get("event_type", ""),
                        "confidence":  "OBSERVED" if a.get("confidence", 0) > 70 else "LOW CONFIDENCE",
                        "first_seen":  a.get("timestamp", ""),
                        "last_seen":   a.get("timestamp", ""),
                        "occurrences": 1,
                        "threat_intel": val in KNOWN_MALICIOUS,
                    })

    # Extract usernames from raw_message heuristically
    usernames = set()
    for a in ctx.alerts:
        msg = a.get("raw_message", "")
        for part in msg.split():
            if part.startswith("user="):
                usernames.add(part[5:].rstrip(".,:"))
    for u in sorted(usernames):
        if u not in ("", "None"):
            iocs.append({
                "value":       u,
                "type":        "Username",
                "source_alert_event": "authentication",
                "confidence":  "OBSERVED",
                "first_seen":  ctx.first_seen,
                "last_seen":   ctx.last_seen,
                "occurrences": 1,
                "threat_intel": False,
            })

    return {
        "generator":   "ioc_generator",
        "incident_id": ctx.incident_id,
        "title":       ctx.title,
        "total_iocs":  len(iocs),
        "iocs":        iocs,
        "export_note": "All IOCs extracted from observed alert data. No external enrichment applied.",
        "warning": "Do NOT blocklist IPs that appear only as destinations without corroborating evidence.",
    }


# ---------------------------------------------------------------------------
# 4. MITRE ATT&CK Chain Generator
# ---------------------------------------------------------------------------

def generate_mitre_chain(ctx: IncidentContext) -> Dict[str, Any]:
    if not ctx.mitre_techniques:
        return {
            "generator":   "mitre_chain",
            "incident_id": ctx.incident_id,
            "title":       ctx.title,
            "chain":       [],
            "summary":     "No MITRE ATT&CK techniques identified for this incident.",
        }

    # Order techniques by tactic sequence
    tactic_order = {t: i for i, t in enumerate(MITRE_TACTIC_ORDER)}
    ordered = sorted(
        ctx.mitre_techniques,
        key=lambda t: tactic_order.get(t.get("tactic", ""), 99),
    )

    chain = []
    for tech in ordered:
        tid = tech.get("technique_id", "")
        # Find supporting alerts
        supporting = [
            a for a in ctx.alerts
            if tid.lower()[:4] in str(a.get("event_type", "")).lower()
            or tid.lower()[:4] in str(a.get("raw_message", "")).lower()
        ]
        chain.append({
            "technique_id":  tid,
            "name":          tech.get("name", ""),
            "tactic":        tech.get("tactic", ""),
            "description":   tech.get("description", ""),
            "confidence":    "OBSERVED",
            "supporting_alerts": len(supporting),
        })

    return {
        "generator":      "mitre_chain",
        "incident_id":    ctx.incident_id,
        "title":          ctx.title,
        "technique_count": len(chain),
        "chain":           chain,
        "summary": (
            f"INC-{ctx.incident_id} maps to {len(chain)} MITRE ATT&CK technique(s) "
            f"across {len({t['tactic'] for t in chain})} tactic(s)."
        ),
    }


# ---------------------------------------------------------------------------
# 5. Threat Report Generator
# ---------------------------------------------------------------------------

def generate_threat_report(ctx: IncidentContext) -> Dict[str, Any]:
    tl = ctx.timeline()
    first = tl[0] if tl else {}
    last  = tl[-1] if tl else {}

    # Affected assets
    assets = sorted(set(
        [a.get("dst_ip") for a in ctx.alerts if a.get("dst_ip") and not a.get("dst_ip", "").endswith("/24")]
    ))

    # Risk assessment text
    risk_text = (
        f"Risk Score: {ctx.risk_score}/100 ({ctx.priority}). "
        f"Confidence: {ctx.confidence}%. "
        f"{'Corroborated by external threat intelligence. ' if ctx.has_threat_intel else ''}"
        f"{'Assessed as likely false positive.' if ctx.is_false_positive else 'Genuine threat indicators present.'}"
    )

    # Potential impact
    impact_lines = []
    if "data_exfiltration" in ctx.event_types or "data_staged" in ctx.event_types:
        impact_lines.append("Potential data breach — sensitive data may have been exfiltrated.")
    if "privilege_escalation" in ctx.event_types:
        impact_lines.append("Privilege escalation confirmed — attacker may have full system control.")
    if "account_manipulation" in ctx.event_types:
        impact_lines.append("Backdoor accounts may persist post-remediation.")
    if "c2_beaconing" in ctx.event_types:
        impact_lines.append("Active C2 channel detected — ongoing attacker access likely.")
    if not impact_lines:
        impact_lines.append("Impact scope requires further investigation.")

    return {
        "generator":     "threat_report",
        "incident_id":   ctx.incident_id,
        "report_title":  f"Threat Report: {ctx.title}",
        "executive_summary": (
            f"INC-{ctx.incident_id} — '{ctx.title}' — represents a {ctx.priority}-priority security incident "
            f"with a risk score of {ctx.risk_score}/100. "
            f"{ctx.alert_count} alerts were correlated from {len(ctx.sources)} telemetry sources. "
            f"{'Threat intelligence confirms malicious actor involvement.' if ctx.has_threat_intel else ''}"
        ),
        "incident_overview": ctx.to_dict(),
        "detection_summary": {
            "total_alerts":    ctx.alert_count,
            "sources":         ctx.sources,
            "event_types":     ctx.event_types,
            "first_detected":  ctx.first_seen,
            "last_activity":   ctx.last_seen,
        },
        "timeline":          tl[:50],
        "affected_assets":   assets or ["Unknown — see alert data"],
        "indicators":        ctx.indicators,
        "mitre_mapping":     ctx.mitre_techniques,
        "risk_assessment":   risk_text,
        "potential_impact":  impact_lines,
        "recommended_actions": _response_actions(ctx),
        "investigation_gaps": _investigation_gaps(ctx),
    }


# ---------------------------------------------------------------------------
# 6. Detection Rule Generator
# ---------------------------------------------------------------------------

def generate_detection_rule(ctx: IncidentContext) -> Dict[str, Any]:
    rules = []
    observed = set(ctx.event_types)

    if "authentication_failure" in observed:
        src_ips_str = " OR ".join(f'src_ip="{ip}"' for ip in ctx.source_ips[:3]) or 'src_ip="*"'
        rules.append({
            "name":        f"Brute Force Detection — INC-{ctx.incident_id}",
            "purpose":     "Detect repeated authentication failures from observed source IPs",
            "log_source":  "Authentication logs (SIEM)",
            "mitre":       "T1110 — Brute Force",
            "severity":    "HIGH",
            "sigma_rule": (
                f"title: Brute Force from {', '.join(ctx.source_ips[:2]) or 'unknown'}\n"
                f"status: experimental\n"
                f"logsource:\n  category: authentication\n"
                f"detection:\n"
                f"  selection:\n    EventType: authentication_failure\n"
                f"    SourceIP|contains:\n"
                + "\n".join(f"      - '{ip}'" for ip in ctx.source_ips[:5])
                + f"\n  timeframe: 5m\n  condition: selection | count() > 5\n"
                f"falsepositives:\n  - Legitimate users with forgotten passwords\n"
                f"level: high"
            ),
            "kql_rule": (
                f"SecurityEvent\n"
                f"| where EventID == 4625\n"
                f"| where IpAddress in ({', '.join(repr(ip) for ip in ctx.source_ips[:5])})\n"
                f"| summarize count() by IpAddress, bin(TimeGenerated, 5m)\n"
                f"| where count_ > 5"
            ),
            "false_positive_considerations": "Internal scanners (Nessus, etc.) may trigger. Add allowlist.",
        })

    if "suspicious_script" in observed or "c2_beaconing" in observed:
        rules.append({
            "name":       f"Suspicious PowerShell / C2 Activity — INC-{ctx.incident_id}",
            "purpose":    "Detect encoded PowerShell execution and beaconing behaviour",
            "log_source": "Process creation + DNS logs",
            "mitre":      "T1059.001 — PowerShell / T1071 — Application Layer Protocol",
            "severity":   "HIGH",
            "sigma_rule": (
                f"title: Encoded PowerShell from {', '.join(ctx.source_ips[:2]) or 'observed hosts'}\n"
                f"status: experimental\n"
                f"logsource:\n  category: process_creation\n"
                f"detection:\n"
                f"  selection:\n    CommandLine|contains: '-EncodedCommand'\n"
                f"    SourceIP|contains:\n"
                + "\n".join(f"      - '{ip}'" for ip in ctx.source_ips[:5])
                + f"\n  condition: selection\nlevel: high"
            ),
            "kql_rule": (
                f"DeviceProcessEvents\n"
                f"| where ProcessCommandLine contains '-EncodedCommand'\n"
                f"| where DeviceId in ({', '.join(repr(ip) for ip in ctx.source_ips[:5])})\n"
                f"| project Timestamp, DeviceName, ProcessCommandLine"
            ),
            "false_positive_considerations": "Legitimate admin scripts may use encoded commands.",
        })

    if "data_exfiltration" in observed or "data_staged" in observed:
        rules.append({
            "name":       f"Data Exfiltration Detection — INC-{ctx.incident_id}",
            "purpose":    "Detect large outbound transfers to observed destination IPs",
            "log_source": "Firewall / Network flow logs",
            "mitre":      "T1048 — Exfiltration Over Alternative Protocol",
            "severity":   "CRITICAL",
            "sigma_rule": (
                f"title: Large Outbound Transfer to {', '.join(ctx.dest_ips[:2]) or 'external'}\n"
                f"status: experimental\n"
                f"logsource:\n  category: network_connection\n"
                f"detection:\n"
                f"  selection:\n    DestinationIP|contains:\n"
                + "\n".join(f"      - '{ip}'" for ip in ctx.dest_ips[:5])
                + f"\n    BytesSent|gt: 100000000\n  condition: selection\nlevel: critical"
            ),
            "kql_rule": (
                f"CommonSecurityLog\n"
                f"| where DestinationIP in ({', '.join(repr(ip) for ip in ctx.dest_ips[:5])})\n"
                f"| where SentBytes > 100000000\n"
                f"| project TimeGenerated, SourceIP, DestinationIP, SentBytes"
            ),
            "false_positive_considerations": "Authorised backup or sync operations. Verify transfer destination.",
        })

    if not rules:
        return {
            "generator":   "detection_rule",
            "incident_id": ctx.incident_id,
            "title":       ctx.title,
            "rules":       [],
            "note": "Insufficient telemetry in this incident to generate reliable detection rules.",
        }

    return {
        "generator":   "detection_rule",
        "incident_id": ctx.incident_id,
        "title":       ctx.title,
        "rules":       rules,
        "note": (
            "Rules generated from observed alert evidence only. "
            "Review and tune before deploying to production SIEM."
        ),
    }


# ---------------------------------------------------------------------------
# 7. Response Playbook Generator
# ---------------------------------------------------------------------------

def _response_actions(ctx: IncidentContext) -> List[str]:
    actions = [f"Escalate INC-{ctx.incident_id} to SOC analyst for immediate review."]
    if ctx.priority in ("CRITICAL", "HIGH"):
        actions.append(f"Block source IP(s) {', '.join(ctx.source_ips[:3])} at perimeter firewall.")
    if "authentication_success" in ctx.event_types:
        actions.append("Disable and audit compromised user accounts. Reset all related credentials.")
    if "privilege_escalation" in ctx.event_types:
        actions.append("Isolate affected hosts from network. Preserve forensic image.")
    if "account_manipulation" in ctx.event_types:
        actions.append("Remove all backdoor accounts identified in evidence. Audit admin group membership.")
    if "c2_beaconing" in ctx.event_types:
        actions.append("Block identified C2 destination IPs/domains. Terminate suspicious DNS queries.")
    if "data_exfiltration" in ctx.event_types or "data_staged" in ctx.event_types:
        actions.append("Identify and classify data accessed. Initiate data breach assessment protocol.")
    return actions


def _investigation_gaps(ctx: IncidentContext) -> List[str]:
    gaps = []
    if not ctx.dest_ips:
        gaps.append("Destination hosts not fully identified — network logs may be incomplete.")
    if ctx.alert_count < 3:
        gaps.append("Low alert count — activity may be under-detected or telemetry gaps exist.")
    if not ctx.has_threat_intel:
        gaps.append("Source IPs not in threat-intel feeds — check manual blacklists and OSINT.")
    return gaps or ["No significant investigation gaps identified based on current telemetry."]


def generate_response_playbook(ctx: IncidentContext) -> Dict[str, Any]:
    steps = [
        {
            "phase":    "Triage",
            "priority": "IMMEDIATE",
            "actions": [
                f"Acknowledge INC-{ctx.incident_id} in SIEM/ticketing system.",
                f"Confirm incident is active: check last_seen = {ctx.last_seen[:19]}.",
                f"Assess priority: {ctx.priority} (Risk: {ctx.risk_score}/100).",
            ],
            "expected_result": "Incident confirmed active and assigned to analyst.",
        },
        {
            "phase":    "Validation",
            "priority": "HIGH",
            "actions": [
                f"Review all {ctx.alert_count} correlated alerts.",
                f"Verify source IP(s) {', '.join(ctx.source_ips[:3])} are not authorised.",
                f"Check {'threat-intel confirms malicious IP.' if ctx.has_threat_intel else 'OSINT / threat-intel for source IPs.'}",
            ],
            "expected_result": "Confirm genuine threat vs. false positive.",
        },
        {
            "phase":    "Containment",
            "priority": "HIGH" if ctx.priority in ("CRITICAL", "HIGH") else "MEDIUM",
            "actions": _response_actions(ctx),
            "expected_result": "Attacker access severed. Lateral movement prevented.",
        },
        {
            "phase":    "Investigation",
            "priority": "HIGH",
            "actions": [
                f"Pull full authentication logs for IPs: {', '.join(ctx.source_ips[:5])}.",
                "Review process creation, network, and file access logs on affected hosts.",
                "Search for persistence mechanisms: scheduled tasks, registry, startup.",
            ] + (["Analyse DNS traffic for C2 patterns."] if "c2_beaconing" in ctx.event_types else []),
            "expected_result": "Full attack path reconstructed. Scope of access understood.",
        },
        {
            "phase":    "Eradication",
            "priority": "HIGH",
            "actions": [
                "Remove malicious files, accounts, and persistence mechanisms identified.",
                "Patch or mitigate exploited vulnerabilities.",
                "Re-image compromised hosts if root-level access was confirmed.",
            ],
            "expected_result": "Threat actor presence removed from environment.",
        },
        {
            "phase":    "Recovery",
            "priority": "MEDIUM",
            "actions": [
                "Restore systems from verified clean backups if required.",
                "Re-enable services after confirming clean state.",
                "Monitor affected assets intensively for 72 hours post-remediation.",
            ],
            "expected_result": "Systems returned to normal operation.",
        },
        {
            "phase":    "Lessons Learned",
            "priority": "LOW",
            "actions": [
                f"Document timeline and findings for INC-{ctx.incident_id}.",
                "Identify detection gaps that allowed initial access.",
                "Update detection rules based on IOCs and TTPs observed.",
                "Review firewall rules and authentication policies.",
            ],
            "expected_result": "Improved detection and prevention posture.",
        },
    ]

    return {
        "generator":    "response_playbook",
        "incident_id":  ctx.incident_id,
        "title":        ctx.title,
        "priority":     ctx.priority,
        "risk_score":   ctx.risk_score,
        "playbook_steps": steps,
        "investigation_gaps": _investigation_gaps(ctx),
    }


# ---------------------------------------------------------------------------
# 8. Threat Hunting Query Generator
# ---------------------------------------------------------------------------

def generate_threat_hunting(ctx: IncidentContext) -> Dict[str, Any]:
    queries = []
    observed = set(ctx.event_types)
    ips_kql  = ", ".join(f'"{ip}"' for ip in ctx.source_ips[:5]) or '"unknown"'
    ips_spl  = " OR ".join(f'src_ip="{ip}"' for ip in ctx.source_ips[:5]) or "src_ip=*"

    if "authentication_failure" in observed or "authentication_success" in observed:
        queries.append({
            "objective":     "Hunt for additional auth activity from observed attacker IPs",
            "mitre":         "T1110 — Brute Force / T1078 — Valid Accounts",
            "data_source":   "Authentication logs (4624/4625 Windows, auth.log Linux)",
            "kql": (
                f"SecurityEvent\n"
                f"| where EventID in (4624, 4625)\n"
                f"| where IpAddress in ({ips_kql})\n"
                f"| summarize count(), make_set(Account) by IpAddress, bin(TimeGenerated, 1h)\n"
                f"| order by count_ desc"
            ),
            "spl": (
                f"index=windows EventCode=4624 OR EventCode=4625 ({ips_spl})\n"
                f"| stats count, values(Account) by IpAddress, span(TimeGenerated, 1h)\n"
                f"| sort -count"
            ),
            "sql": (
                f"SELECT src_ip, event_type, COUNT(*) as cnt, MIN(timestamp) as first_seen\n"
                f"FROM alerts\n"
                f"WHERE src_ip IN ({', '.join(repr(ip) for ip in ctx.source_ips[:5])})\n"
                f"  AND event_type IN ('authentication_failure','authentication_success')\n"
                f"GROUP BY src_ip, event_type ORDER BY cnt DESC"
            ),
            "expected_findings": "Additional auth attempts from same IPs not captured in this incident.",
        })

    if "suspicious_script" in observed or "c2_beaconing" in observed:
        queries.append({
            "objective":   "Hunt for encoded PowerShell and beacon patterns on affected hosts",
            "mitre":       "T1059.001 — PowerShell / T1071 — Application Layer Protocol",
            "data_source": "Process creation + DNS logs",
            "kql": (
                f"DeviceProcessEvents\n"
                f"| where ProcessCommandLine contains '-EncodedCommand'\n"
                f"    or ProcessCommandLine contains 'IEX'\n"
                f"    or ProcessCommandLine contains 'Invoke-Expression'\n"
                f"| where DeviceName in ({ips_kql})\n"
                f"| project Timestamp, DeviceName, FileName, ProcessCommandLine"
            ),
            "spl": (
                f"index=endpoint ({ips_spl})\n"
                f"| search CommandLine=\"*EncodedCommand*\" OR CommandLine=\"*IEX*\"\n"
                f"| table _time, host, CommandLine"
            ),
            "sql": (
                f"SELECT src_ip, raw_message, timestamp FROM alerts\n"
                f"WHERE (event_type='suspicious_script' OR event_type='c2_beaconing')\n"
                f"  AND src_ip IN ({', '.join(repr(ip) for ip in ctx.source_ips[:5])})\n"
                f"ORDER BY timestamp"
            ),
            "expected_findings": "Obfuscated PowerShell or periodic DNS queries to same destinations.",
        })

    if "data_exfiltration" in observed or "data_staged" in observed:
        queries.append({
            "objective":   "Hunt for additional data staging and outbound transfer activity",
            "mitre":       "T1048 — Exfiltration / T1074 — Data Staged",
            "data_source": "Firewall / Network flow logs",
            "kql": (
                f"CommonSecurityLog\n"
                f"| where SourceIP in ({ips_kql})\n"
                f"    or DestinationIP in ({', '.join(repr(ip) for ip in ctx.dest_ips[:5])})\n"
                f"| where SentBytes > 10000000\n"
                f"| summarize total_bytes=sum(SentBytes) by SourceIP, DestinationIP, bin(TimeGenerated, 1h)"
            ),
            "spl": (
                f"index=network ({ips_spl})\n"
                f"| stats sum(bytes_out) as total_out by src_ip, dest_ip\n"
                f"| where total_out > 10000000"
            ),
            "sql": (
                f"SELECT src_ip, dst_ip, COUNT(*) as events, MIN(timestamp) as first_seen\n"
                f"FROM alerts\n"
                f"WHERE event_type IN ('data_exfiltration','data_staged')\n"
                f"GROUP BY src_ip, dst_ip ORDER BY events DESC"
            ),
            "expected_findings": "Recurring large transfers to same external destinations.",
        })

    if not queries:
        queries.append({
            "objective":   f"General activity hunt for observed source IPs",
            "mitre":       "General",
            "data_source": "All available logs",
            "kql":         f"union SecurityEvent, CommonSecurityLog\n| where IpAddress in ({ips_kql})\n| order by TimeGenerated desc\n| take 500",
            "spl":         f"index=* ({ips_spl}) | sort -_time | head 500",
            "sql":         f"SELECT * FROM alerts WHERE src_ip IN ({', '.join(repr(ip) for ip in ctx.source_ips[:5])}) ORDER BY timestamp DESC LIMIT 500",
            "expected_findings": "Any activity from observed attacker IPs not captured in this incident.",
        })

    return {
        "generator":   "threat_hunting",
        "incident_id": ctx.incident_id,
        "title":       ctx.title,
        "queries":     queries,
        "note": "Queries reference observed IPs and event types from this incident. Tune thresholds for your environment.",
    }


# ---------------------------------------------------------------------------
# 9. Executive Brief Generator
# ---------------------------------------------------------------------------

def generate_executive_brief(ctx: IncidentContext) -> Dict[str, Any]:
    severity_word = {"CRITICAL": "critical", "HIGH": "high-severity", "MEDIUM": "medium-severity", "LOW": "low-severity"}.get(ctx.priority, "security")
    src = ctx.source_ips[0] if ctx.source_ips else "an unidentified external source"
    dst = ctx.dest_ips[0] if ctx.dest_ips else "internal systems"

    # What happened
    what_lines = [f"ThreatLens detected a {severity_word} security incident (INC-{ctx.incident_id}): '{ctx.title}'."]
    if "authentication_failure" in ctx.event_types and "authentication_success" in ctx.event_types:
        what_lines.append(f"The attacker at {src} launched a brute-force attack and successfully authenticated to {dst}.")
    elif "authentication_failure" in ctx.event_types:
        what_lines.append(f"Multiple failed login attempts were detected from {src} against {dst}.")
    if "privilege_escalation" in ctx.event_types:
        what_lines.append("Elevated system privileges were obtained, indicating the attacker gained administrative control.")
    if "data_exfiltration" in ctx.event_types:
        what_lines.append("Sensitive data was transferred to an external destination.")
    if "c2_beaconing" in ctx.event_types:
        what_lines.append("A command-and-control channel was established, suggesting ongoing attacker access.")
    if "account_manipulation" in ctx.event_types:
        what_lines.append("Backdoor accounts were created to maintain persistent access.")

    # Why it matters
    impact_lines = []
    if ctx.priority == "CRITICAL":
        impact_lines.append("This is a critical incident requiring immediate executive attention.")
    if ctx.has_threat_intel:
        impact_lines.append("The source IP is linked to known malicious actors in our threat-intelligence database.")
    if "data_exfiltration" in ctx.event_types:
        impact_lines.append("A data breach may have occurred, triggering potential regulatory notification obligations.")

    # Status
    status_line = (
        f"The incident is currently {ctx.status}. "
        f"Risk score: {ctx.risk_score}/100. Confidence: {ctx.confidence}%."
    )

    # Recommended action
    if ctx.priority == "CRITICAL":
        action = "Immediate executive decision required: authorise incident response, notify legal/compliance, and consider customer communication."
    elif ctx.priority == "HIGH":
        action = "SOC team escalation authorised. Expect remediation within 4 hours. Update stakeholders at next status checkpoint."
    else:
        action = "Security team investigating. No immediate executive action required. Monitor for escalation."

    brief_text = " ".join(what_lines + impact_lines + [status_line, action])
    # Target ~150-200 words
    words = brief_text.split()
    if len(words) > 220:
        brief_text = " ".join(words[:200]) + "…"

    return {
        "generator":    "executive_brief",
        "incident_id":  ctx.incident_id,
        "title":        ctx.title,
        "priority":     ctx.priority,
        "risk_score":   ctx.risk_score,
        "brief":        brief_text,
        "what_happened":       " ".join(what_lines),
        "why_it_matters":      " ".join(impact_lines) or "No immediate external impact identified.",
        "affected_assets":     ctx.dest_ips[:5] or ["Internal systems — see incident detail"],
        "current_status":      status_line,
        "recommended_action":  action,
        "word_count":          len(brief_text.split()),
    }


# ---------------------------------------------------------------------------
# 10. Safe Attack Simulation Generator
# ---------------------------------------------------------------------------

def generate_attack_simulation(ctx: IncidentContext) -> Dict[str, Any]:
    """
    Generates SAFE, DEFENSIVE simulation scenarios for security testing.
    Does NOT generate real attack payloads, malware, or destructive commands.
    """
    observed = set(ctx.event_types)
    simulations = []

    if "authentication_failure" in observed:
        simulations.append({
            "scenario":          "Credential Brute-Force Simulation",
            "objective":         "Validate that repeated authentication failures from a single source trigger alerts and lockout policies.",
            "simulated_activity": (
                f"Generate {min(ctx.alert_count, 50)} authentication failures from a test IP "
                f"against a non-production test account in a lab environment. "
                "Use a password list of publicly known common passwords against the test account only."
            ),
            "expected_logs":     ["EventID 4625 (Windows) or auth.log failure entries"],
            "expected_alerts":   ["Brute Force Detection rule triggered", "Account lockout policy engaged"],
            "mitre_techniques":  ["T1110 — Brute Force"],
            "detection_opportunities": ["SIEM correlation rule on N failures in M minutes"],
            "defensive_controls":      ["Account lockout policy", "MFA enforcement", "IP reputation blocking"],
            "safety_note":       "Use a dedicated test account. Do not test against production accounts or external systems.",
        })

    if "suspicious_script" in observed or "c2_beaconing" in observed:
        simulations.append({
            "scenario":          "Suspicious PowerShell Process-Creation Simulation",
            "objective":         "Validate EDR detection of encoded PowerShell and anomalous child process creation.",
            "simulated_activity": (
                "Execute a benign encoded PowerShell command (e.g., Base64-encoded Write-Host 'test') "
                "on an isolated lab endpoint. Observe process-creation telemetry and EDR alerts. "
                "Do not use this command on production systems."
            ),
            "expected_logs":     ["Process creation events with -EncodedCommand flag"],
            "expected_alerts":   ["EDR alert on encoded PowerShell", "SIEM Sigma rule trigger"],
            "mitre_techniques":  ["T1059.001 — PowerShell"],
            "detection_opportunities": ["Process command-line monitoring", "Script block logging"],
            "defensive_controls":      ["PowerShell Constrained Language Mode", "Script Block Logging", "AMSI"],
            "safety_note":       "Use benign payload (Write-Host / Get-Date). Never simulate actual malware on production.",
        })

    if "data_exfiltration" in observed or "data_staged" in observed:
        simulations.append({
            "scenario":          "Data Staging & Transfer Simulation",
            "objective":         "Validate DLP and network monitoring detection of large outbound transfers.",
            "simulated_activity": (
                "Create a test file (non-sensitive, e.g. random data) of >50MB on an isolated lab host. "
                "Transfer it to an internal test server using curl/scp. "
                "Observe firewall and DLP alerts. Do not use real data or external destinations."
            ),
            "expected_logs":     ["Large outbound transfer in firewall logs", "DLP policy match"],
            "expected_alerts":   ["Network anomaly alert on bytes transferred", "DLP quarantine notification"],
            "mitre_techniques":  ["T1048 — Exfiltration", "T1074 — Data Staged"],
            "detection_opportunities": ["Firewall NetFlow anomaly detection", "DLP byte-threshold rules"],
            "defensive_controls":      ["DLP policies", "Egress firewall rules", "Network monitoring"],
            "safety_note":       "Use synthetic data only. Never stage or transfer real sensitive data in simulations.",
        })

    if not simulations:
        simulations.append({
            "scenario":          "General Anomaly Detection Simulation",
            "objective":         "Validate baseline SIEM alerting on network anomalies.",
            "simulated_activity": (
                f"Generate test log entries replicating the observed event types: {', '.join(observed)} "
                "in a lab SIEM instance. Confirm correlation rules fire as expected."
            ),
            "expected_logs":     ["Lab SIEM event ingestion confirmed"],
            "expected_alerts":   ["Correlation rule triggered for observed event types"],
            "mitre_techniques":  ctx.mitre_ids[:3],
            "detection_opportunities": ["SIEM correlation tuning"],
            "defensive_controls":      ["SIEM rule review"],
            "safety_note":       "Only simulate in isolated lab environment. Never against production systems.",
        })

    return {
        "generator":    "attack_simulation",
        "incident_id":  ctx.incident_id,
        "title":        ctx.title,
        "disclaimer": (
            "All simulations are DEFENSIVE ONLY. "
            "No real attack payloads, malware, or credential theft instructions are provided. "
            "Only simulate in authorised, isolated lab environments."
        ),
        "simulations":  simulations,
    }


# ---------------------------------------------------------------------------
# Full Intelligence Package
# ---------------------------------------------------------------------------

def generate_full_package(ctx: IncidentContext) -> Dict[str, Any]:
    return {
        "generator":    "full_package",
        "incident_id":  ctx.incident_id,
        "title":        ctx.title,
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "threat_intelligence": generate_threat_intelligence(ctx),
        "attack_scenario":     generate_attack_scenario(ctx),
        "iocs":                generate_iocs(ctx),
        "mitre_chain":         generate_mitre_chain(ctx),
        "threat_report":       generate_threat_report(ctx),
        "detection_rules":     generate_detection_rule(ctx),
        "response_playbook":   generate_response_playbook(ctx),
        "threat_hunting":      generate_threat_hunting(ctx),
        "executive_brief":     generate_executive_brief(ctx),
        "attack_simulation":   generate_attack_simulation(ctx),
    }
