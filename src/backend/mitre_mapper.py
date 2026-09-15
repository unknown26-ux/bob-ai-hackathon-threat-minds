"""
mitre_mapper.py — Maps alert patterns to MITRE ATT&CK techniques.

Uses a local keyword table — no external MITRE API required.
"""

from typing import Any, Dict, List


TECHNIQUES: Dict[str, Dict] = {
    "T1110": {
        "technique_id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries use brute force to gain access to accounts.",
    },
    "T1110.003": {
        "technique_id": "T1110.003",
        "name": "Password Spraying",
        "tactic": "Credential Access",
        "description": "Use of a single password against many accounts to avoid lockout.",
    },
    "T1046": {
        "technique_id": "T1046",
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Adversaries scan for open ports and running services.",
    },
    "T1078": {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Persistence",
        "description": "Adversaries obtain and abuse existing account credentials.",
    },
    "T1098": {
        "technique_id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "description": "Adversaries manipulate accounts to maintain or expand access.",
    },
    "T1059": {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries abuse command interpreters to execute commands.",
    },
    "T1059.001": {
        "technique_id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries use PowerShell commands and scripts for execution.",
    },
    "T1074": {
        "technique_id": "T1074",
        "name": "Data Staged",
        "tactic": "Collection",
        "description": "Adversaries stage collected data for later exfiltration.",
    },
    "T1048": {
        "technique_id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries steal data over non-standard protocols.",
    },
    "T1071": {
        "technique_id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries communicate using application layer protocols (DNS, HTTP).",
    },
    "T1021": {
        "technique_id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries use remote services to move laterally.",
    },
    "T1068": {
        "technique_id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries exploit vulnerabilities to elevate privileges.",
    },
}

# Each entry: (keywords_to_match, [technique_ids])
# Keywords are matched against event_type + raw_message (lowercase)
KEYWORD_MAP = [
    (["authentication_failure", "failed login", "failed ssh", "failed rdp", "brute"], ["T1110"]),
    (["password spray", "spray pattern", "1 attempt per account"],                    ["T1110.003"]),
    (["port_scan", "network scan", "ports probed", "probed port", "scan detected"],   ["T1046"]),
    (["authentication_success", "successful login", "successful rdp", "valid account", "successful ssh"], ["T1078"]),
    (["rdp", "remote desktop", "remote service"],                                      ["T1021"]),
    (["account_manipulation", "new local admin", "account created", "svc_update"],    ["T1098"]),
    (["powershell", "invoke-webrequest", "encoded ps", "scheduled task"],              ["T1059", "T1059.001"]),
    (["suspicious_script", "bash -i", "interactive shell", "scripting"],              ["T1059"]),
    (["privilege_escalation", "sudo bash", "root shell", "privesc"],                  ["T1068"]),
    (["data_exfiltration", "exfiltration", "outbound transfer", "unusual outbound"],  ["T1048"]),
    (["data_staged", "archive created", "tar.gz", "staging"],                         ["T1074"]),
    (["c2_beaconing", "dns tunnel", "dns txt", "beacon", "c2"],                       ["T1071"]),
]


def map_techniques(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Given a list of normalized alert dicts, return a deduplicated list
    of MITRE technique dicts matched from the keyword table.
    """
    matched_ids: set = set()

    for alert in alerts:
        searchable = " ".join([
            str(alert.get("event_type", "")),
            str(alert.get("raw_message", "")),
        ]).lower()

        for keywords, technique_ids in KEYWORD_MAP:
            if any(kw in searchable for kw in keywords):
                matched_ids.update(technique_ids)

    return [TECHNIQUES[tid] for tid in sorted(matched_ids) if tid in TECHNIQUES]
