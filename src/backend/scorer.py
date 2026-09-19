"""
scorer.py — Deterministic 0-100 risk score and confidence for each incident.

No ML — all rules are transparent and explainable.
Score breakdown is stored and displayed in the dashboard.
"""

from typing import Any, Dict, List, Tuple

# IPs known to be authorised internal scanners → false positive indicator
KNOWN_SCANNERS = {"10.0.0.5", "10.0.0.6", "192.168.0.200"}

# Confirmed malicious IPs — matches MALICIOUS_POOL in demo_data.py
# These trigger the threat_intel_score bonus in the risk model
KNOWN_MALICIOUS = {"185.22.14.8", "91.108.56.200", "203.0.113.99"}

SEVERITY_WEIGHTS = {"critical": 40, "high": 30, "medium": 15, "low": 5}


def _false_positive_analysis(
    alerts: List[Dict[str, Any]],
    has_threat_intel: bool,
    mitre_techniques: List[Dict[str, Any]],
    risk_score: float,
    confidence: float,
    src_ips: set,
    is_known_scanner: bool,
) -> Dict[str, Any]:
    """
    Return an evidence-based false-positive estimate derived from the existing
    ThreatLens scoring inputs. This is an estimated FP likelihood, not a
    measured false-positive rate from historical ground truth.
    """
    if not alerts:
        return {
            "score": 100,
            "percentage": 100,
            "likelihood": "High",
            "reason": "Insufficient evidence to assess malicious activity; the signal is too weak to distinguish a true threat from benign behavior.",
            "factors": ["Insufficient evidence"],
            "measurement": "Estimated false-positive likelihood (not a measured FPR)",
        }

    avg_conf = (
        sum(int(a.get("confidence", 50)) for a in alerts) / len(alerts)
        if alerts else 50.0
    )
    event_types = {a.get("event_type") for a in alerts if a.get("event_type")}
    all_low_severity = all(a.get("severity", "low") == "low" for a in alerts)
    low_confidence = all(int(a.get("confidence", 50)) < 40 for a in alerts)
    weak_evidence = all_low_severity and low_confidence
    conflicting = "authentication_failure" in event_types and "authentication_success" in event_types
    isolated_signal = len(alerts) <= 1 or len(event_types) <= 1
    corroborated = len(alerts) >= 3 or len(event_types) >= 2
    strong_evidence = (
        has_threat_intel or avg_conf >= 75 or len(mitre_techniques) >= 2 or risk_score >= 70
    )

    fp_score = 0.0
    factors = []

    if is_known_scanner:
        fp_score += 45.0
        factors.append("Known benign scanner IP")
    if low_confidence:
        fp_score += 30.0
        factors.append("Low detection confidence")
    if weak_evidence:
        fp_score += 20.0
        factors.append("Weak evidence")
    if isolated_signal:
        fp_score += 20.0
        factors.append("Single isolated indicator")
    if not has_threat_intel and not corroborated:
        fp_score += 10.0
        factors.append("No corroborating threat intel")
    if conflicting:
        fp_score += 15.0
        factors.append("Conflicting indicators")

    if has_threat_intel:
        fp_score -= 20.0
        factors.append("Strong threat-intel match")
    if corroborated and avg_conf >= 70:
        fp_score -= 20.0
        factors.append("Multiple corroborating indicators")
    if strong_evidence and not is_known_scanner:
        fp_score -= 15.0
        factors.append("High-quality evidence")

    fp_score = max(0.0, min(100.0, round(fp_score, 1)))

    if not factors:
        factors = ["Insufficient evidence"]

    seen = []
    ordered_factors = []
    for factor in factors:
        if factor not in seen:
            seen.append(factor)
            ordered_factors.append(factor)

    if fp_score >= 75:
        likelihood = "High"
        reason = (
            "The alert pattern is dominated by weak, low-confidence, or benign-scanner indicators, "
            "with limited corroboration from the current incident data."
        )
    elif fp_score >= 45:
        likelihood = "Medium"
        reason = (
            "There is some suspicious context, but the evidence is not strongly corroborated and the "
            "signal remains vulnerable to false-positive interpretation."
        )
    else:
        likelihood = "Low"
        reason = (
            "The incident contains multiple corroborating indicators and/or high-quality threat-intel evidence, "
            "which materially lowers the estimated false-positive likelihood."
        )

    return {
        "score": int(fp_score),
        "percentage": int(fp_score),
        "likelihood": likelihood,
        "reason": reason,
        "factors": ordered_factors,
        "measurement": "Estimated false-positive likelihood (not a measured FPR)",
    }


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

    is_known_scanner = bool(src_ips) and all(ip in KNOWN_SCANNERS for ip in src_ips)
    false_positive = _false_positive_analysis(
        alerts=alerts,
        has_threat_intel=has_threat_intel,
        mitre_techniques=mitre_techniques,
        risk_score=risk_score,
        confidence=confidence,
        src_ips=src_ips,
        is_known_scanner=is_known_scanner,
    )

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
        "false_positive":    false_positive,
    }

    return risk_score, confidence, explanation
