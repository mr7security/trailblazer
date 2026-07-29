"""
TrailBlazer :: MITRE ATT&CK Technique Registry
Mapeo de técnicas ATT&CK Enterprise usadas por los collectors.
"""

from __future__ import annotations

BASE_URL = "https://attack.mitre.org/techniques"

# ── Registro de técnicas ──────────────────────────────────────────────────────
# Formato: "T####[.###]" → {"name": str, "tactic": str}
TECHNIQUES: dict[str, dict] = {
    # Execution
    "T1059.001": {"name": "PowerShell",                      "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell",           "tactic": "Execution"},
    "T1059.004": {"name": "Unix Shell",                      "tactic": "Execution"},
    "T1204.002": {"name": "Malicious File",                  "tactic": "Execution"},

    # Persistence
    "T1053.003": {"name": "Cron",                            "tactic": "Persistence"},
    "T1053.005": {"name": "Scheduled Task",                  "tactic": "Persistence"},
    "T1543.002": {"name": "Systemd Service",                 "tactic": "Persistence"},
    "T1543.003": {"name": "Windows Service",                 "tactic": "Persistence"},
    "T1546.003": {"name": "Windows Management Instrumentation", "tactic": "Persistence"},
    "T1546.010": {"name": "AppInit DLLs",                   "tactic": "Persistence"},
    "T1546.012": {"name": "Image File Execution Options Injection", "tactic": "Persistence"},
    "T1546.015": {"name": "Component Object Model Hijacking", "tactic": "Persistence"},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": "Persistence"},

    # Privilege Escalation
    "T1548.001": {"name": "Setuid and Setgid",               "tactic": "Privilege Escalation"},
    "T1078.001": {"name": "Local Accounts",                  "tactic": "Privilege Escalation"},
    "T1078.002": {"name": "Domain Accounts",                 "tactic": "Privilege Escalation"},

    # Defense Evasion
    "T1036.005": {"name": "Match Legitimate Name or Location", "tactic": "Defense Evasion"},
    "T1036.007": {"name": "Double File Extension",           "tactic": "Defense Evasion"},
    "T1055.012": {"name": "Process Hollowing",               "tactic": "Defense Evasion"},
    "T1070.001": {"name": "Clear Windows Event Logs",        "tactic": "Defense Evasion"},
    "T1070.006": {"name": "Timestomp",                       "tactic": "Defense Evasion"},
    "T1562.001": {"name": "Disable or Modify Tools",         "tactic": "Defense Evasion"},
    "T1574.002": {"name": "DLL Side-Loading",                "tactic": "Defense Evasion"},

    # Credential Access
    "T1003.001": {"name": "LSASS Memory",                   "tactic": "Credential Access"},
    "T1110":     {"name": "Brute Force",                    "tactic": "Credential Access"},
    "T1552.001": {"name": "Credentials In Files",           "tactic": "Credential Access"},
    "T1552.004": {"name": "Private Keys",                   "tactic": "Credential Access"},
    "T1555.004": {"name": "Windows Credential Manager",    "tactic": "Credential Access"},

    # Discovery
    "T1057":     {"name": "Process Discovery",              "tactic": "Discovery"},
    "T1049":     {"name": "System Network Connections Discovery", "tactic": "Discovery"},

    # Lateral Movement
    "T1021.004": {"name": "SSH",                            "tactic": "Lateral Movement"},

    # Command and Control
    "T1071":     {"name": "Application Layer Protocol",    "tactic": "C2"},
    "T1071.001": {"name": "Web Protocols",                 "tactic": "C2"},
    "T1095":     {"name": "Non-Application Layer Protocol", "tactic": "C2"},
    "T1105":     {"name": "Ingress Tool Transfer",         "tactic": "C2"},

    # Exfiltration
    "T1041":     {"name": "Exfiltration Over C2 Channel",  "tactic": "Exfiltration"},

    # Impact
    "T1136.001": {"name": "Local Account (Create)",        "tactic": "Persistence"},

    # Resource Development
    "T1588.002": {"name": "Tool (Acquire)",                "tactic": "Resource Development"},
}


def technique_url(tid: str) -> str:
    """Devuelve la URL completa de una técnica ATT&CK."""
    # T1059.001 → /T1059/001
    parts = tid.split(".")
    path  = "/".join(parts)
    return f"{BASE_URL}/{path}/"


def get(tid: str) -> dict:
    """Devuelve {name, tactic, url} para un technique ID, o dict vacío si no existe."""
    if tid not in TECHNIQUES:
        return {}
    t = TECHNIQUES[tid]
    return {
        "technique_id":   tid,
        "technique_name": t["name"],
        "technique_tactic": t["tactic"],
        "technique_url":  technique_url(tid),
    }
