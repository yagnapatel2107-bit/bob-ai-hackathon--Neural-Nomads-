"""
mitre_map.py
------------
Maps alert keywords/behavior tags to MITRE ATT&CK (Enterprise) techniques.

This is a lightweight keyword-based mapper, deliberately simple and
auditable so judges/analysts can see exactly why a technique was assigned.
Swap TECHNIQUE_KEYWORDS for a call to the real MITRE ATT&CK STIX dataset
(attack.mitre.org / TAXII server) for production use — the interface
(`map_keywords_to_techniques`) stays the same either way.
"""

from typing import List, Dict, Set

TECHNIQUE_KEYWORDS: Dict[str, Dict[str, str]] = {
    "recon_scan":        {"id": "T1595", "name": "Active Scanning",                  "tactic": "Reconnaissance"},
    "phishing":          {"id": "T1566", "name": "Phishing",                         "tactic": "Initial Access"},
    "exploit_public_app":{"id": "T1190", "name": "Exploit Public-Facing Application","tactic": "Initial Access"},
    "valid_accounts":    {"id": "T1078", "name": "Valid Accounts",                   "tactic": "Initial Access"},
    "powershell":        {"id": "T1059.001","name": "PowerShell",                    "tactic": "Execution"},
    "scheduled_task":    {"id": "T1053", "name": "Scheduled Task/Job",               "tactic": "Persistence"},
    "priv_escalation":   {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "obfuscation":       {"id": "T1027", "name": "Obfuscated Files or Information",   "tactic": "Defense Evasion"},
    "credential_dump":   {"id": "T1003", "name": "OS Credential Dumping",            "tactic": "Credential Access"},
    "network_sniffing":  {"id": "T1040", "name": "Network Sniffing",                 "tactic": "Discovery"},
    "lateral_movement":  {"id": "T1021", "name": "Remote Services",                  "tactic": "Lateral Movement"},
    "data_staging":      {"id": "T1074", "name": "Data Staged",                      "tactic": "Collection"},
    "c2_beacon":         {"id": "T1071", "name": "Application Layer Protocol (C2)",  "tactic": "Command and Control"},
    "exfiltration":      {"id": "T1041", "name": "Exfiltration Over C2 Channel",     "tactic": "Exfiltration"},
    "ransomware":        {"id": "T1486", "name": "Data Encrypted for Impact",        "tactic": "Impact"},
    "unusual_movement":  {"id": "T1583.006","name": "Acquire Infrastructure: Web Services (proxy for physical/satellite anomaly)", "tactic": "Resource Development"},
}

# Normalize common raw-tag synonyms onto the canonical keyword set above.
SYNONYMS = {
    "scan": "recon_scan", "portscan": "recon_scan", "probing": "recon_scan",
    "phish": "phishing", "spearphish": "phishing",
    "cve": "exploit_public_app", "webshell": "exploit_public_app",
    "stolen_creds": "valid_accounts", "login_anomaly": "valid_accounts",
    "ps1": "powershell", "encoded_command": "powershell",
    "persistence": "scheduled_task", "cron": "scheduled_task",
    "escalation": "priv_escalation",
    "packed": "obfuscation", "encrypted_payload": "obfuscation",
    "mimikatz": "credential_dump", "lsass": "credential_dump",
    "sniffer": "network_sniffing", "arp_spoof": "network_sniffing",
    "smb": "lateral_movement", "rdp": "lateral_movement", "psexec": "lateral_movement",
    "archive": "data_staging", "zip_creation": "data_staging",
    "beacon": "c2_beacon", "c2": "c2_beacon", "dns_tunnel": "c2_beacon",
    "large_upload": "exfiltration", "outbound_transfer": "exfiltration",
    "encryption_spike": "ransomware", "file_extension_change": "ransomware",
    "convoy": "unusual_movement", "flight_path_deviation": "unusual_movement",
    "asset_relocation": "unusual_movement",
}


def map_keywords_to_techniques(keywords: List[str]) -> List[Dict[str, str]]:
    """Return de-duplicated MITRE technique dicts matched from a list of tags."""
    matched: Set[str] = set()
    for kw in keywords:
        key = kw.lower().strip()
        canonical = SYNONYMS.get(key, key if key in TECHNIQUE_KEYWORDS else None)
        if canonical:
            matched.add(canonical)
    return [TECHNIQUE_KEYWORDS[k] for k in matched]
