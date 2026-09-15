"""
demo_data.py — 27 realistic simulated security alerts for ThreatLens demo.

Three sources:
  A. SIEM / authentication logs
  B. Network / firewall alerts
  C. Threat intelligence feed

Designed to produce ~8 correlated incidents from 27 raw alerts,
with one obvious CRITICAL incident from attacker 185.22.14.8 → 10.0.0.15.
"""

DEMO_ALERTS = [

    # =========================================================================
    # INCIDENT A — CRITICAL: Coordinated brute-force + scan + threat-intel hit
    # Attacker: 185.22.14.8  Target: 10.0.0.15 (web-server)
    # =========================================================================
    {
        "timestamp": "2024-01-15T08:00:10Z", "source": "ThreatIntel",
        "src_ip": "185.22.14.8", "dst_ip": None,
        "event_type": "threat_intel_match", "severity": "critical", "confidence": 98,
        "indicator": "185.22.14.8",
        "raw_message": "IP 185.22.14.8 confirmed in threat-intel feed: APT-41 C2 node, 47 abuse reports in last 24 h.",
    },
    {
        "timestamp": "2024-01-15T08:01:05Z", "source": "Firewall",
        "src_ip": "185.22.14.8", "dst_ip": "10.0.0.15",
        "event_type": "port_scan", "severity": "high", "confidence": 90,
        "indicator": "185.22.14.8",
        "raw_message": "Port scan: 185.22.14.8 probed 1024 ports on 10.0.0.15 in 45 s. Ports 22,80,443,3389 found open.",
    },
    {
        "timestamp": "2024-01-15T08:02:00Z", "source": "SIEM",
        "src_ip": "185.22.14.8", "dst_ip": "10.0.0.15",
        "event_type": "authentication_failure", "severity": "high", "confidence": 92,
        "indicator": "185.22.14.8",
        "raw_message": "Failed SSH login: user=root from 185.22.14.8 to 10.0.0.15. Attempt 1/5.",
    },
    {
        "timestamp": "2024-01-15T08:02:18Z", "source": "SIEM",
        "src_ip": "185.22.14.8", "dst_ip": "10.0.0.15",
        "event_type": "authentication_failure", "severity": "high", "confidence": 92,
        "indicator": "185.22.14.8",
        "raw_message": "Failed SSH login: user=admin from 185.22.14.8 to 10.0.0.15. Attempt 2/5.",
    },
    {
        "timestamp": "2024-01-15T08:02:35Z", "source": "SIEM",
        "src_ip": "185.22.14.8", "dst_ip": "10.0.0.15",
        "event_type": "authentication_failure", "severity": "high", "confidence": 92,
        "indicator": "185.22.14.8",
        "raw_message": "Failed SSH login: user=deploy from 185.22.14.8 to 10.0.0.15. Attempt 3/5.",
    },
    {
        "timestamp": "2024-01-15T08:02:52Z", "source": "SIEM",
        "src_ip": "185.22.14.8", "dst_ip": "10.0.0.15",
        "event_type": "authentication_failure", "severity": "high", "confidence": 92,
        "indicator": "185.22.14.8",
        "raw_message": "Failed SSH login: user=ubuntu from 185.22.14.8 to 10.0.0.15. Attempt 4/5.",
    },
    {
        "timestamp": "2024-01-15T08:03:10Z", "source": "SIEM",
        "src_ip": "185.22.14.8", "dst_ip": "10.0.0.15",
        "event_type": "authentication_success", "severity": "critical", "confidence": 95,
        "indicator": "185.22.14.8",
        "raw_message": "SUCCESSFUL SSH login: user=ubuntu from 185.22.14.8 to 10.0.0.15 after 4 failures. BRUTE FORCE SUCCESS.",
    },
    {
        "timestamp": "2024-01-15T08:04:30Z", "source": "SIEM",
        "src_ip": "185.22.14.8", "dst_ip": "10.0.0.15",
        "event_type": "privilege_escalation", "severity": "critical", "confidence": 94,
        "indicator": "185.22.14.8",
        "raw_message": "Privilege escalation: user ubuntu ran 'sudo bash -i' on 10.0.0.15 — interactive root shell spawned.",
    },

    # =========================================================================
    # INCIDENT B — HIGH: Lateral movement via RDP spray
    # Attacker: 203.0.113.99  Targets: multiple internal hosts
    # =========================================================================
    {
        "timestamp": "2024-01-15T09:10:00Z", "source": "Firewall",
        "src_ip": "203.0.113.99", "dst_ip": "10.0.2.0/24",
        "event_type": "port_scan", "severity": "high", "confidence": 82,
        "indicator": "203.0.113.99",
        "raw_message": "RDP scan: 203.0.113.99 probed port 3389 across entire 10.0.2.0/24 subnet.",
    },
    {
        "timestamp": "2024-01-15T09:11:10Z", "source": "SIEM",
        "src_ip": "203.0.113.99", "dst_ip": "10.0.2.5",
        "event_type": "authentication_failure", "severity": "medium", "confidence": 75,
        "indicator": "203.0.113.99",
        "raw_message": "Failed RDP login: user=administrator from 203.0.113.99 to 10.0.2.5.",
    },
    {
        "timestamp": "2024-01-15T09:11:45Z", "source": "SIEM",
        "src_ip": "203.0.113.99", "dst_ip": "10.0.2.10",
        "event_type": "authentication_failure", "severity": "medium", "confidence": 75,
        "indicator": "203.0.113.99",
        "raw_message": "Failed RDP login: user=administrator from 203.0.113.99 to 10.0.2.10.",
    },
    {
        "timestamp": "2024-01-15T09:12:30Z", "source": "SIEM",
        "src_ip": "203.0.113.99", "dst_ip": "10.0.2.20",
        "event_type": "authentication_success", "severity": "high", "confidence": 80,
        "indicator": "203.0.113.99",
        "raw_message": "Successful RDP login: user=administrator from 203.0.113.99 to 10.0.2.20 (finance-server).",
    },

    # =========================================================================
    # INCIDENT C — HIGH: Data exfiltration from compromised host
    # Internal compromised host: 10.0.1.50 → external: 91.108.56.200
    # =========================================================================
    {
        "timestamp": "2024-01-15T10:05:00Z", "source": "Firewall",
        "src_ip": "10.0.1.50", "dst_ip": "91.108.56.200",
        "event_type": "data_exfiltration", "severity": "critical", "confidence": 88,
        "indicator": "91.108.56.200",
        "raw_message": "Unusual outbound transfer: 10.0.1.50 → 91.108.56.200 — 780 MB in 120 s on port 443.",
    },
    {
        "timestamp": "2024-01-15T10:06:00Z", "source": "ThreatIntel",
        "src_ip": "91.108.56.200", "dst_ip": None,
        "event_type": "threat_intel_match", "severity": "high", "confidence": 91,
        "indicator": "91.108.56.200",
        "raw_message": "IP 91.108.56.200 in threat-intel: known data-staging server used by TA505 group.",
    },
    {
        "timestamp": "2024-01-15T10:07:00Z", "source": "SIEM",
        "src_ip": "10.0.1.50", "dst_ip": "91.108.56.200",
        "event_type": "data_staged", "severity": "high", "confidence": 85,
        "indicator": "91.108.56.200",
        "raw_message": "Archive created and uploaded: /tmp/.hidden/archive.tar.gz transferred via curl to 91.108.56.200.",
    },

    # =========================================================================
    # INCIDENT D — MEDIUM: PowerShell execution on endpoint
    # Endpoint: 10.0.3.22
    # =========================================================================
    {
        "timestamp": "2024-01-15T11:00:00Z", "source": "SIEM",
        "src_ip": "10.0.3.22", "dst_ip": "10.0.3.1",
        "event_type": "suspicious_script", "severity": "high", "confidence": 72,
        "indicator": "10.0.3.22",
        "raw_message": "PowerShell execution: Invoke-WebRequest downloading payload from internal share on 10.0.3.22.",
    },
    {
        "timestamp": "2024-01-15T11:01:30Z", "source": "SIEM",
        "src_ip": "10.0.3.22", "dst_ip": "10.0.3.1",
        "event_type": "account_manipulation", "severity": "high", "confidence": 70,
        "indicator": "10.0.3.22",
        "raw_message": "New local admin account 'svc_update' created via PowerShell on 10.0.3.22.",
    },

    # =========================================================================
    # INCIDENT E — MEDIUM: Password spray on VPN gateway
    # Attacker: 45.33.100.55
    # =========================================================================
    {
        "timestamp": "2024-01-15T12:00:00Z", "source": "SIEM",
        "src_ip": "45.33.100.55", "dst_ip": "10.0.0.1",
        "event_type": "authentication_failure", "severity": "medium", "confidence": 65,
        "indicator": "45.33.100.55",
        "raw_message": "VPN auth failure: user=jsmith from 45.33.100.55. Password spray pattern detected (1 attempt per account).",
    },
    {
        "timestamp": "2024-01-15T12:00:30Z", "source": "SIEM",
        "src_ip": "45.33.100.55", "dst_ip": "10.0.0.1",
        "event_type": "authentication_failure", "severity": "medium", "confidence": 65,
        "indicator": "45.33.100.55",
        "raw_message": "VPN auth failure: user=mjones from 45.33.100.55. Password spray pattern detected.",
    },
    {
        "timestamp": "2024-01-15T12:01:00Z", "source": "SIEM",
        "src_ip": "45.33.100.55", "dst_ip": "10.0.0.1",
        "event_type": "authentication_failure", "severity": "medium", "confidence": 65,
        "indicator": "45.33.100.55",
        "raw_message": "VPN auth failure: user=bwilson from 45.33.100.55. Password spray pattern detected.",
    },

    # =========================================================================
    # INCIDENT F — LOW / Likely False Positive: Internal vuln scanner
    # Scanner: 10.0.0.5
    # =========================================================================
    {
        "timestamp": "2024-01-15T13:00:00Z", "source": "Firewall",
        "src_ip": "10.0.0.5", "dst_ip": "10.0.1.0/24",
        "event_type": "port_scan", "severity": "low", "confidence": 20,
        "indicator": "10.0.0.5",
        "raw_message": "Scheduled scan: 10.0.0.5 (Nessus scanner) performing routine assessment of 10.0.1.0/24.",
    },
    {
        "timestamp": "2024-01-15T13:02:00Z", "source": "SIEM",
        "src_ip": "10.0.0.5", "dst_ip": "10.0.1.10",
        "event_type": "authentication_failure", "severity": "low", "confidence": 18,
        "indicator": "10.0.0.5",
        "raw_message": "Auth probe from 10.0.0.5 consistent with Nessus credentialed scan — expected behaviour.",
    },

    # =========================================================================
    # INCIDENT G — MEDIUM: DNS tunneling / C2 beaconing
    # Infected host: 10.0.4.11
    # =========================================================================
    {
        "timestamp": "2024-01-15T14:10:00Z", "source": "Firewall",
        "src_ip": "10.0.4.11", "dst_ip": "8.8.8.8",
        "event_type": "c2_beaconing", "severity": "high", "confidence": 76,
        "indicator": "10.0.4.11",
        "raw_message": "DNS tunneling detected: 10.0.4.11 sending high-entropy DNS TXT queries at 30 s intervals (C2 beacon pattern).",
    },
    {
        "timestamp": "2024-01-15T14:11:00Z", "source": "SIEM",
        "src_ip": "10.0.4.11", "dst_ip": "10.0.4.1",
        "event_type": "suspicious_script", "severity": "medium", "confidence": 68,
        "indicator": "10.0.4.11",
        "raw_message": "Scheduled task created on 10.0.4.11 running encoded PowerShell every 30 s.",
    },

    # =========================================================================
    # INCIDENT H — LOW: Informational — successful auth from new geo
    # =========================================================================
    {
        "timestamp": "2024-01-15T15:00:00Z", "source": "SIEM",
        "src_ip": "176.34.22.101", "dst_ip": "10.0.0.50",
        "event_type": "authentication_success", "severity": "low", "confidence": 40,
        "indicator": "176.34.22.101",
        "raw_message": "Successful VPN login from new geolocation (PL) for user=hbrown. First login from this country.",
    },
]
