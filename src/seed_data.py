from datetime import datetime, timedelta


def get_sample_alerts():
    """Return synthetic threat intelligence alerts for testing."""

    now = datetime.utcnow()

    return [
        {
            "Alert ID": "D2-001",
            "Timestamp": (now - timedelta(minutes=10)).isoformat(),
            "Source": "SIEM Log",
            "MITRE Tactic": "Initial Access",
            "MITRE Technique": "T1566 - Phishing",
            "Confidence": 92,
            "Severity": 85,
            "Asset Crit": 5,
        },
        {
            "Alert ID": "D2-002",
            "Timestamp": (now - timedelta(minutes=25)).isoformat(),
            "Source": "Cyber Sensor",
            "MITRE Tactic": "Execution",
            "MITRE Technique": "T1059 - Command & Scripting",
            "Confidence": 78,
            "Severity": 70,
            "Asset Crit": 4,
        },
        {
            "Alert ID": "D2-003",
            "Timestamp": (now - timedelta(minutes=40)).isoformat(),
            "Source": "Intel Report",
            "MITRE Tactic": "Persistence",
            "MITRE Technique": "T1078 - Valid Accounts",
            "Confidence": 55,
            "Severity": 45,
            "Asset Crit": 2,
        },
        {
            "Alert ID": "D2-004",
            "Timestamp": (now - timedelta(minutes=55)).isoformat(),
            "Source": "Satellite Feed",
            "MITRE Tactic": "Initial Access",
            "MITRE Technique": "T1190 - Exploit Facing App",
            "Confidence": 88,
            "Severity": 90,
            "Asset Crit": 5,
        },
    ]


if __name__ == "__main__":
    for alert in get_sample_alerts():
        print(alert)
