"""
demo_data.py — Multi-scenario demo alert generator for ThreatLens.

Six distinct attack scenarios. Each call produces:
  - different source/destination IPs (randomised from realistic pools)
  - varied severity profiles (severity mix changes per run)
  - different alert counts and event types
  - different correlation group counts → different incident counts

This guarantees visible changes in EVERY stat card on each Load Demo Data click:
  Total Alerts, Total Incidents, Critical, High Risk, Genuine Threats
"""

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

SCENARIOS: Dict[str, Dict] = {
    "credential_attack": {
        "id":          "credential_attack",
        "name":        "Credential Attack Campaign",
        "description": "Multi-stage brute-force and credential-stuffing from external threat actor.",
    },
    "powershell_execution": {
        "id":          "powershell_execution",
        "name":        "Suspicious PowerShell Execution",
        "description": "Encoded PowerShell activity with scheduled persistence and C2 beaconing.",
    },
    "data_exfiltration": {
        "id":          "data_exfiltration",
        "name":        "Data Exfiltration Campaign",
        "description": "Staged data collection and large outbound transfer to known threat actor.",
    },
    "network_recon": {
        "id":          "network_recon",
        "name":        "Network Reconnaissance & Lateral Movement",
        "description": "External scanning followed by lateral RDP movement across subnets.",
    },
    "account_manipulation": {
        "id":          "account_manipulation",
        "name":        "Account Manipulation & Privilege Escalation",
        "description": "Rogue service account creation, privilege escalation, and admin abuse.",
    },
    "mixed_low_severity": {
        "id":          "mixed_low_severity",
        "name":        "Low-Severity Mixed Activity",
        "description": "Routine scanning, geo-anomalous logins, and informational events.",
    },
}

# ---------------------------------------------------------------------------
# IP pools — varied severity/reputation per pool
# ---------------------------------------------------------------------------

# Known-malicious pool: picking from here will raise risk via scorer.py threat intel
MALICIOUS_POOL = ["185.22.14.8", "91.108.56.200", "203.0.113.99"]

# Suspicious external (not confirmed malicious — medium risk result)
SUSPICIOUS_POOL = [
    "45.33.100.55", "194.165.16.77", "176.97.210.55",
    "37.120.141.0", "89.248.165.22", "104.244.72.115",
]

# All external — randomly pick either malicious or suspicious
ALL_EXTERNAL = MALICIOUS_POOL + SUSPICIOUS_POOL

# Known-clean internal scanners (always false positive)
SCANNER_POOL = ["10.0.0.5", "10.0.0.6", "192.168.0.200"]

INTERNAL_SUBNETS = ["10.0.1", "10.0.2", "10.0.3", "172.16.4", "192.168.10"]


def _rand_external(force_malicious: bool = False) -> str:
    """Return an external IP. ~40% chance of being known-malicious for risk variety."""
    if force_malicious or random.random() < 0.4:
        return random.choice(MALICIOUS_POOL)
    return random.choice(SUSPICIOUS_POOL)


def _rand_internal() -> str:
    sub = random.choice(INTERNAL_SUBNETS)
    return f"{sub}.{random.randint(10, 250)}"


def _rand_scanner() -> str:
    return random.choice(SCANNER_POOL)


def _ts(base: datetime, offset_minutes: float) -> str:
    return (base + timedelta(minutes=offset_minutes)).isoformat()


def _base() -> datetime:
    """Random timestamp within the last 7 days."""
    now = datetime.now(timezone.utc)
    return now - timedelta(
        days=random.randint(0, 6),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
    )


# ---------------------------------------------------------------------------
# Severity variation helpers
# ---------------------------------------------------------------------------

def _vary_severity(base: str) -> str:
    """
    Introduce severity variation per run so risk scores differ.
    30% chance to downgrade one level, 20% chance to upgrade.
    """
    order = ["low", "medium", "high", "critical"]
    idx = order.index(base) if base in order else 2
    r = random.random()
    if r < 0.20 and idx < 3:    # upgrade
        idx += 1
    elif r < 0.45 and idx > 0:  # downgrade
        idx -= 1
    return order[idx]


def _vary_confidence(base: int) -> int:
    """Add ±15 jitter to confidence values."""
    return max(10, min(99, base + random.randint(-15, 15)))


# ---------------------------------------------------------------------------
# Scenario A — Credential Attack Campaign
# ---------------------------------------------------------------------------

def _scenario_credential_attack() -> List[Dict]:
    b        = _base()
    attacker = _rand_external()   # may or may not be known-malicious
    target   = _rand_internal()
    target2  = _rand_internal()
    vpn_gw   = "10.0.0.1"

    # Vary the attack profile: sometimes only failures, sometimes success+priv esc
    has_success  = random.random() > 0.3   # 70% chance brute force succeeds
    has_priv_esc = has_success and random.random() > 0.4  # 60% of successes escalate
    spray_count  = random.randint(2, 6)

    alerts = []

    # Threat intel hit (only if attacker is known-malicious)
    if attacker in MALICIOUS_POOL:
        alerts.append({
            "timestamp": _ts(b, 0), "source": "ThreatIntel",
            "src_ip": attacker, "dst_ip": None,
            "event_type": "threat_intel_match",
            "severity": "critical", "confidence": _vary_confidence(96),
            "indicator": attacker,
            "raw_message": f"IP {attacker} confirmed in threat-intel feed: credential-stuffing botnet.",
        })

    # Port scan
    alerts.append({
        "timestamp": _ts(b, 1), "source": "Firewall",
        "src_ip": attacker, "dst_ip": target,
        "event_type": "port_scan",
        "severity": _vary_severity("high"), "confidence": _vary_confidence(88),
        "indicator": attacker,
        "raw_message": f"Port scan: {attacker} probed {random.randint(256,1024)} ports on {target}. SSH/RDP found open.",
    })

    # Auth failures
    users = random.sample(["root","admin","ubuntu","deploy","git","operator","svc"], spray_count)
    for i, u in enumerate(users):
        alerts.append({
            "timestamp": _ts(b, 1.5 + i * 0.3), "source": "SIEM",
            "src_ip": attacker, "dst_ip": target,
            "event_type": "authentication_failure",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(90),
            "indicator": attacker,
            "raw_message": f"Failed SSH login: user={u} from {attacker} to {target}. Attempt {i+1}/{spray_count}.",
        })

    if has_success:
        alerts.append({
            "timestamp": _ts(b, 3.5), "source": "SIEM",
            "src_ip": attacker, "dst_ip": target,
            "event_type": "authentication_success",
            "severity": _vary_severity("critical"), "confidence": _vary_confidence(94),
            "indicator": attacker,
            "raw_message": f"SUCCESSFUL SSH login: user={users[-1]} from {attacker} to {target} after {spray_count} failures.",
        })

    if has_priv_esc:
        alerts.append({
            "timestamp": _ts(b, 4.5), "source": "SIEM",
            "src_ip": attacker, "dst_ip": target,
            "event_type": "privilege_escalation",
            "severity": _vary_severity("critical"), "confidence": _vary_confidence(92),
            "indicator": attacker,
            "raw_message": f"Privilege escalation on {target}: 'sudo bash -i' — root shell spawned.",
        })

    # Separate password-spray group on VPN (different indicator = separate incident)
    spray_ip = _rand_external()
    for i in range(spray_count):
        alerts.append({
            "timestamp": _ts(b, 10 + i * 0.5), "source": "SIEM",
            "src_ip": spray_ip, "dst_ip": vpn_gw,
            "event_type": "authentication_failure",
            "severity": _vary_severity("medium"), "confidence": _vary_confidence(66),
            "indicator": spray_ip,   # DIFFERENT indicator → separate incident group
            "raw_message": f"VPN auth failure: user=user{i:02d} from {spray_ip}. Spray pattern.",
        })

    # Optional second target
    if random.random() > 0.5:
        alerts.append({
            "timestamp": _ts(b, 15), "source": "SIEM",
            "src_ip": attacker, "dst_ip": target2,
            "event_type": "authentication_failure",
            "severity": _vary_severity("medium"), "confidence": _vary_confidence(72),
            "indicator": attacker,
            "raw_message": f"Failed RDP login: user=administrator from {attacker} to {target2}.",
        })

    return alerts


# ---------------------------------------------------------------------------
# Scenario B — Suspicious PowerShell Execution
# ---------------------------------------------------------------------------

def _scenario_powershell() -> List[Dict]:
    b       = _base()
    ps_host = _rand_internal()
    c2_host = _rand_internal()   # different IP = separate correlation group
    dns_ext = "8.8.8.8"

    has_account_backdoor = random.random() > 0.4
    has_lateral          = random.random() > 0.5

    alerts = [
        {
            "timestamp": _ts(b, 0), "source": "SIEM",
            "src_ip": ps_host, "dst_ip": "10.0.0.1",
            "event_type": "suspicious_script",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(83),
            "indicator": ps_host,
            "raw_message": f"PowerShell download cradle on {ps_host}: Invoke-WebRequest payload | IEX.",
        },
        {
            "timestamp": _ts(b, 0.5), "source": "SIEM",
            "src_ip": ps_host, "dst_ip": None,
            "event_type": "suspicious_script",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(80),
            "indicator": ps_host,
            "raw_message": f"Encoded PowerShell on {ps_host}: -EncodedCommand <base64> — obfuscation.",
        },
        {
            "timestamp": _ts(b, 1), "source": "SIEM",
            "src_ip": ps_host, "dst_ip": None,
            "event_type": "suspicious_script",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(77),
            "indicator": ps_host,
            "raw_message": f"Scheduled task 'svchost_upd' on {ps_host}: encoded PS every 30s — persistence.",
        },
    ]

    if has_account_backdoor:
        alerts.append({
            "timestamp": _ts(b, 1.5), "source": "SIEM",
            "src_ip": ps_host, "dst_ip": None,
            "event_type": "account_manipulation",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(84),
            "indicator": ps_host,
            "raw_message": f"New local admin 'svc_update' created via PS on {ps_host} — backdoor.",
        })

    # C2 host — separate indicator so it becomes a SEPARATE incident
    alerts += [
        {
            "timestamp": _ts(b, 2), "source": "Firewall",
            "src_ip": c2_host, "dst_ip": dns_ext,
            "event_type": "c2_beaconing",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(77),
            "indicator": c2_host,   # different indicator = separate incident
            "raw_message": f"DNS tunneling on {c2_host}: high-entropy TXT queries every 30s.",
        },
        {
            "timestamp": _ts(b, 2.5), "source": "SIEM",
            "src_ip": c2_host, "dst_ip": None,
            "event_type": "suspicious_script",
            "severity": _vary_severity("medium"), "confidence": _vary_confidence(68),
            "indicator": c2_host,
            "raw_message": f"Scheduled task on {c2_host}: encoded PS beacon every 30s.",
        },
    ]

    if has_lateral:
        alerts.append({
            "timestamp": _ts(b, 3), "source": "SIEM",
            "src_ip": ps_host, "dst_ip": c2_host,
            "event_type": "authentication_success",
            "severity": _vary_severity("medium"), "confidence": _vary_confidence(63),
            "indicator": ps_host,
            "raw_message": f"Remote login from {ps_host} to {c2_host} using svc_update — lateral.",
        })

    return alerts


# ---------------------------------------------------------------------------
# Scenario C — Data Exfiltration
# ---------------------------------------------------------------------------

def _scenario_exfiltration() -> List[Dict]:
    b         = _base()
    comp_host = _rand_internal()
    exfil_dst = _rand_external(force_malicious=True)   # always known-malicious destination
    staging   = _rand_internal()
    mb        = random.randint(200, 900)

    has_dns_exfil  = random.random() > 0.4
    has_second_stager = random.random() > 0.5

    alerts = [
        {
            "timestamp": _ts(b, 0), "source": "Firewall",
            "src_ip": comp_host, "dst_ip": exfil_dst,
            "event_type": "data_exfiltration",
            "severity": _vary_severity("critical"), "confidence": _vary_confidence(90),
            "indicator": exfil_dst,
            "raw_message": f"Unusual outbound: {comp_host} → {exfil_dst} — {mb} MB in 120s on port 443.",
        },
        {
            "timestamp": _ts(b, 1), "source": "ThreatIntel",
            "src_ip": exfil_dst, "dst_ip": None,
            "event_type": "threat_intel_match",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(91),
            "indicator": exfil_dst,
            "raw_message": f"IP {exfil_dst} in threat-intel: known data-staging server (TA505).",
        },
        {
            "timestamp": _ts(b, 1.5), "source": "SIEM",
            "src_ip": comp_host, "dst_ip": exfil_dst,
            "event_type": "data_staged",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(85),
            "indicator": exfil_dst,
            "raw_message": f"Archive /tmp/.data/archive.tar.gz on {comp_host} — transferred via curl to {exfil_dst}.",
        },
    ]

    if has_second_stager:
        alerts.append({
            "timestamp": _ts(b, 2), "source": "SIEM",
            "src_ip": staging, "dst_ip": exfil_dst,
            "event_type": "data_staged",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(82),
            "indicator": exfil_dst,
            "raw_message": f"Second staging: {staging} writing to same archive → {exfil_dst}.",
        })

    if has_dns_exfil:
        alerts.append({
            "timestamp": _ts(b, 3), "source": "Firewall",
            "src_ip": comp_host, "dst_ip": "8.8.8.8",
            "event_type": "c2_beaconing",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(74),
            "indicator": comp_host,   # different indicator
            "raw_message": f"DNS exfiltration on {comp_host}: encoded data in TXT queries — secondary channel.",
        })

    # Lateral auth (separate indicator)
    auth_src = staging if has_second_stager else _rand_internal()
    alerts.append({
        "timestamp": _ts(b, 4), "source": "SIEM",
        "src_ip": auth_src, "dst_ip": comp_host,
        "event_type": "authentication_success",
        "severity": _vary_severity("medium"), "confidence": _vary_confidence(70),
        "indicator": auth_src,   # different indicator = potentially separate group
        "raw_message": f"Login from {auth_src} to {comp_host} — attacker pivoting to collect more data.",
    })

    return alerts


# ---------------------------------------------------------------------------
# Scenario D — Network Reconnaissance & Lateral Movement
# ---------------------------------------------------------------------------

def _scenario_recon() -> List[Dict]:
    b         = _base()
    recon_src = _rand_external()
    int_host1 = _rand_internal()
    int_host2 = _rand_internal()
    finance   = f"10.0.2.{random.randint(10, 30)}"
    port_count = random.randint(512, 2048)

    has_lateral_success = random.random() > 0.35
    has_smb_pivot       = has_lateral_success and random.random() > 0.5

    alerts = [
        {
            "timestamp": _ts(b, 0), "source": "Firewall",
            "src_ip": recon_src, "dst_ip": "10.0.0.0/24",
            "event_type": "port_scan",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(84),
            "indicator": recon_src,
            "raw_message": f"External scan: {recon_src} probed 10.0.0.0/24 — {port_count} ports touched.",
        },
        {
            "timestamp": _ts(b, 2), "source": "Firewall",
            "src_ip": recon_src, "dst_ip": "10.0.2.0/24",
            "event_type": "port_scan",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(81),
            "indicator": recon_src,
            "raw_message": f"RDP scan: {recon_src} probed port 3389 across 10.0.2.0/24.",
        },
        {
            "timestamp": _ts(b, 3), "source": "SIEM",
            "src_ip": recon_src, "dst_ip": int_host1,
            "event_type": "authentication_failure",
            "severity": _vary_severity("medium"), "confidence": _vary_confidence(73),
            "indicator": recon_src,
            "raw_message": f"Failed RDP login: user=administrator from {recon_src} to {int_host1}.",
        },
        {
            "timestamp": _ts(b, 3.5), "source": "SIEM",
            "src_ip": recon_src, "dst_ip": int_host2,
            "event_type": "authentication_failure",
            "severity": _vary_severity("medium"), "confidence": _vary_confidence(73),
            "indicator": recon_src,
            "raw_message": f"Failed RDP login: user=administrator from {recon_src} to {int_host2}.",
        },
    ]

    if has_lateral_success:
        alerts.append({
            "timestamp": _ts(b, 4), "source": "SIEM",
            "src_ip": recon_src, "dst_ip": finance,
            "event_type": "authentication_success",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(80),
            "indicator": recon_src,
            "raw_message": f"Successful RDP: {recon_src} → {finance} (finance-server) — lateral movement.",
        })

    if has_smb_pivot:
        alerts.append({
            "timestamp": _ts(b, 5), "source": "SIEM",
            "src_ip": finance, "dst_ip": int_host1,
            "event_type": "authentication_success",
            "severity": _vary_severity("medium"), "confidence": _vary_confidence(68),
            "indicator": finance,   # different indicator = potentially separate group
            "raw_message": f"SMB pivot: {finance} → {int_host1} — attacker moving laterally.",
        })

    return alerts


# ---------------------------------------------------------------------------
# Scenario E — Account Manipulation & Privilege Escalation
# ---------------------------------------------------------------------------

def _scenario_account_manip() -> List[Dict]:
    b        = _base()
    attacker = _rand_external()
    ws       = _rand_internal()
    server   = _rand_internal()

    has_group_mod  = random.random() > 0.4
    has_priv_esc   = random.random() > 0.3
    has_pth        = has_priv_esc and random.random() > 0.5
    has_sec_account = random.random() > 0.5

    alerts = [
        {
            "timestamp": _ts(b, 0), "source": "SIEM",
            "src_ip": attacker, "dst_ip": ws,
            "event_type": "authentication_success",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(79),
            "indicator": attacker,
            "raw_message": f"Login from unexpected IP {attacker} to {ws} — possible stolen credential.",
        },
        {
            "timestamp": _ts(b, 1), "source": "SIEM",
            "src_ip": ws, "dst_ip": None,
            "event_type": "account_manipulation",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(87),
            "indicator": ws,   # pivot to internal source = new incident group
            "raw_message": f"New local admin 'svc_backup' created via PowerShell on {ws}.",
        },
    ]

    if has_group_mod:
        alerts.append({
            "timestamp": _ts(b, 1.5), "source": "SIEM",
            "src_ip": ws, "dst_ip": None,
            "event_type": "account_manipulation",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(85),
            "indicator": ws,
            "raw_message": f"User added to 'Domain Admins' from {ws} — privilege escalation via group policy.",
        })

    alerts.append({
        "timestamp": _ts(b, 2), "source": "SIEM",
        "src_ip": ws, "dst_ip": None,
        "event_type": "suspicious_script",
        "severity": _vary_severity("high"), "confidence": _vary_confidence(80),
        "indicator": ws,
        "raw_message": f"Scheduled task 'updchk32' on {ws} — encoded PS persistence.",
    })

    if has_priv_esc:
        alerts.append({
            "timestamp": _ts(b, 3), "source": "SIEM",
            "src_ip": ws, "dst_ip": server,
            "event_type": "privilege_escalation",
            "severity": _vary_severity("critical"), "confidence": _vary_confidence(90),
            "indicator": ws,
            "raw_message": f"Privilege escalation: {ws} UAC bypass on {server} — SYSTEM access obtained.",
        })

    if has_pth:
        alerts.append({
            "timestamp": _ts(b, 4), "source": "SIEM",
            "src_ip": ws, "dst_ip": server,
            "event_type": "authentication_success",
            "severity": _vary_severity("high"), "confidence": _vary_confidence(83),
            "indicator": ws,
            "raw_message": f"Pass-the-hash: {ws} → {server} using NTLM hash of svc_backup.",
        })

    if has_sec_account:
        alerts.append({
            "timestamp": _ts(b, 4.5), "source": "SIEM",
            "src_ip": server, "dst_ip": None,
            "event_type": "account_manipulation",
            "severity": _vary_severity("medium"), "confidence": _vary_confidence(73),
            "indicator": server,   # different indicator = separate incident
            "raw_message": f"Backdoor account 'helpdesk_svc' created on {server}.",
        })

    return alerts


# ---------------------------------------------------------------------------
# Scenario F — Low-Severity Mixed Activity
# ---------------------------------------------------------------------------

def _scenario_low_severity() -> List[Dict]:
    b        = _base()
    scanner  = _rand_scanner()
    geo_ip   = f"176.34.{random.randint(10, 99)}.{random.randint(1, 254)}"
    new_dev  = _rand_internal()
    scan_targets = random.randint(1, 3)

    alerts = []
    for i in range(scan_targets):
        target = _rand_internal()
        alerts.append({
            "timestamp": _ts(b, i * 2), "source": "Firewall",
            "src_ip": scanner, "dst_ip": f"10.0.{i+1}.0/24",
            "event_type": "port_scan",
            "severity": "low", "confidence": _vary_confidence(18),
            "indicator": scanner,
            "raw_message": f"Scheduled scan: {scanner} (Nessus) assessing 10.0.{i+1}.0/24.",
        })
        alerts.append({
            "timestamp": _ts(b, i * 2 + 1), "source": "SIEM",
            "src_ip": scanner, "dst_ip": target,
            "event_type": "authentication_failure",
            "severity": "low", "confidence": _vary_confidence(15),
            "indicator": scanner,
            "raw_message": f"Auth probe from {scanner} on {target} — Nessus credentialed scan.",
        })

    alerts.append({
        "timestamp": _ts(b, 60), "source": "SIEM",
        "src_ip": geo_ip, "dst_ip": "10.0.0.50",
        "event_type": "authentication_success",
        "severity": "low", "confidence": _vary_confidence(36),
        "indicator": geo_ip,
        "raw_message": f"VPN login from new geo (PL) for user=hbrown from {geo_ip}. First from this region.",
    })

    alerts.append({
        "timestamp": _ts(b, 65), "source": "SIEM",
        "src_ip": new_dev, "dst_ip": "10.0.0.50",
        "event_type": "authentication_success",
        "severity": "low", "confidence": _vary_confidence(33),
        "indicator": new_dev,
        "raw_message": f"Login from new device {new_dev} — user onboarding or BYOD.",
    })

    return alerts


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_GENERATORS = {
    "credential_attack":    _scenario_credential_attack,
    "powershell_execution": _scenario_powershell,
    "data_exfiltration":    _scenario_exfiltration,
    "network_recon":        _scenario_recon,
    "account_manipulation": _scenario_account_manip,
    "mixed_low_severity":   _scenario_low_severity,
}


def get_demo_alerts(scenario_id: Optional[str] = None) -> Tuple[List[Dict], str]:
    """
    Returns (alerts_list, scenario_id).
    If scenario_id is None or empty string, picks randomly.
    """
    if not scenario_id:
        scenario_id = random.choice(list(_GENERATORS.keys()))
    if scenario_id not in _GENERATORS:
        raise KeyError(f"Unknown scenario: {scenario_id!r}. Valid: {list(_GENERATORS)}")
    return _GENERATORS[scenario_id](), scenario_id


def list_scenarios() -> List[Dict]:
    return list(SCENARIOS.values())


# Backward-compat shim
DEMO_ALERTS = _scenario_credential_attack()
