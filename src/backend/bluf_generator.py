"""
bluf_generator.py — Commander-level BLUF summary generator.

BLUF = Bottom Line Up Front. Template-based, deterministic.
Covers: what happened, attacker, target, evidence, MITRE, risk, actions.
"""

from typing import Any, Dict, List


def generate_bluf(
    title: str,
    alerts: List[Dict[str, Any]],
    mitre_techniques: List[Dict[str, Any]],
    explanation: Dict[str, Any],
) -> str:
    risk_score   = explanation.get("risk_score", 0)
    priority     = explanation.get("priority", "LOW")
    confidence   = explanation.get("confidence", 50)
    is_fp        = explanation.get("is_false_positive", False)
    alert_count  = explanation.get("alert_count", len(alerts))
    has_intel    = explanation.get("threat_intel_match", False)

    src_ips   = sorted({a.get("src_ip")  for a in alerts if a.get("src_ip")})
    dst_ips   = sorted({a.get("dst_ip")  for a in alerts if a.get("dst_ip")})
    evt_types = sorted({a.get("event_type") for a in alerts if a.get("event_type")})

    src_str   = ", ".join(src_ips[:3])  or "unknown source"
    dst_str   = ", ".join(dst_ips[:3])  or "internal assets"
    evts_str  = ", ".join(e.replace("_", " ") for e in evt_types)

    mitre_str = (
        ", ".join(f"{t['technique_id']} ({t['name']})" for t in mitre_techniques)
        if mitre_techniques else "none identified"
    )

    # Recommended action based on priority ------------------------------------
    if is_fp:
        action = (
            "No immediate action required. "
            "Verify this is an authorised scanner and add to allowlist if confirmed."
        )
    elif priority == "CRITICAL":
        action = (
            "IMMEDIATE ACTION: Isolate affected host(s), block source IP at perimeter, "
            "revoke any credentials used, preserve forensic evidence, "
            "and initiate full incident response."
        )
    elif priority == "HIGH":
        action = (
            "Investigate within 1 hour. Block source IP, review authentication logs "
            "on affected hosts, and escalate to the security operations team."
        )
    elif priority == "MEDIUM":
        action = (
            "Investigate within 4 hours. Review related logs, confirm whether "
            "activity is authorised, and monitor for escalation."
        )
    else:
        action = "Log and monitor. Review at next security standup."

    intel_note = (
        " Source IP confirmed in threat-intelligence feed as known malicious actor."
        if has_intel else ""
    )
    fp_note = (
        " ASSESSMENT: This activity is consistent with a FALSE POSITIVE."
        if is_fp else ""
    )

    bluf = (
        f"[{priority} | Risk: {risk_score}/100 | Confidence: {confidence}%] "
        f"{title}. "
        f"{alert_count} correlated alert(s) from {src_str} targeting {dst_str}. "
        f"Observed: {evts_str}.{intel_note}{fp_note} "
        f"MITRE ATT&CK: {mitre_str}. "
        f"RECOMMENDED ACTION: {action}"
    )

    return bluf
