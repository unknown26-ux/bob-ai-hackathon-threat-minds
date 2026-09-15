"""
scorer.py — Deterministic 0-100 risk score and confidence for each incident.

No ML — all rules are transparent and explainable.
Score breakdown is stored and displayed in the dashboard.
"""

from typing import Any, Dict, List, Tuple

# IPs known to be authorised internal scanners → false positive indicator
KNOWN_SCANNERS = {"10.0.0.5", "10.0.0.6", "192.168.0.200"}

# Confirmed malicious IPs from demo threat-intel feed
KNOWN_MALICIOUS = {"185.22.14.8", "91.108.56.200", "203.0.113.99"}

SEVERITY_WEIGHTS = {"critical": 40, "high": 30, "medium": 15, "low": 5}


def score_incident(
    alerts: List[Dict[str, Any]],
    mitre_techniques: List[Dict[str, Any]],
) -> Tuple[float, float, Dict[str, Any]]:
    """
    Returns (risk_score 0-100, confidence 0-100, explanation dict).

    Factors:
      severity_score     — highest severity across alerts          (0-40)
      volume_score       — number of correlated alerts             (0-20)
      threat_intel_score — IP matches known-bad list               (0-25)
      mitre_score        — MITRE technique coverage                (0-10)
      fp_penalty         — likely false positive deduction         (-30)
    """

    # 1. Severity (max severity weight, 0-40) ---------------------------------
    severity_score = float(max(
        (SEVERITY_WEIGHTS.get(a.get("severity", "low"), 5) for a in alerts),
        default=5,
    ))

    # 2. Alert volume (0-20, 3 pts each, max 20) ------------------------------
    volume_score = min(20.0, len(alerts) * 3.0)

    # 3. Threat intel match (0-25) --------------------------------------------
    src_ips = {a.get("src_ip") for a in alerts if a.get("src_ip")}
    indicators = {a.get("indicator") for a in alerts if a.get("indicator")}
    all_iocs = src_ips | indicators

    has_threat_intel = bool(all_iocs & KNOWN_MALICIOUS)
    threat_intel_score = 25.0 if has_threat_intel else 0.0

    # 4. MITRE coverage (2.5 pts per technique, 0-10) -------------------------
    mitre_score = min(10.0, len(mitre_techniques) * 2.5)

    # 5. False positive penalty -----------------------------------------------
    is_fp = (
        bool(src_ips) and all(ip in KNOWN_SCANNERS for ip in src_ips)
    ) or (
        all(a.get("severity") == "low" for a in alerts) and
        all(int(a.get("confidence", 50)) < 40 for a in alerts)
    )
    fp_penalty = 30.0 if is_fp else 0.0

    # Confidence: average of alert confidences + boosts/penalties ------------
    avg_conf = (
        sum(int(a.get("confidence", 50)) for a in alerts) / len(alerts)
        if alerts else 50.0
    )
    confidence = avg_conf
    if has_threat_intel:
        confidence = min(100.0, confidence + 10.0)
    if is_fp:
        confidence = max(0.0, confidence - 35.0)
    confidence = round(confidence, 1)

    # Final risk score --------------------------------------------------------
    raw = severity_score + volume_score + threat_intel_score + mitre_score - fp_penalty
    risk_score = round(max(0.0, min(100.0, raw)), 1)

    # Priority label ----------------------------------------------------------
    if risk_score >= 90:
        priority = "CRITICAL"
    elif risk_score >= 70:
        priority = "HIGH"
    elif risk_score >= 40:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    explanation = {
        "severity_score":    severity_score,
        "volume_score":      volume_score,
        "threat_intel_score": threat_intel_score,
        "mitre_score":       mitre_score,
        "fp_penalty":        fp_penalty,
        "risk_score":        risk_score,
        "confidence":        confidence,
        "priority":          priority,
        "is_false_positive": is_fp,
        "alert_count":       len(alerts),
        "threat_intel_match": has_threat_intel,
    }

    return risk_score, confidence, explanation
