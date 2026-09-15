import json
from typing import Dict, List, Any

class ThreatIntelligenceEngine:
    """Backend engine for multi-source correlation, false positive filtering,
    MITRE ATT&CK mapping, and BLUF generation.""" 

    def __init__(self):
        self.mitre_db = {
            "satcom": {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols"},
            "script": {"id": "T1059.004", "name": "Command & Scripting Interpreter: Unix Shell"},
            "brute_force": {"id": "T1110", "name": "Brute Force"},
            "exfiltration": {"id": "T1041", "name": "Exfiltration Over C2 Channel"}
        }

    def is_false_positive(self, alert: Dict[str, Any]) -> bool:
        """Filters out low-confidence noise or routine maintenance flags."""
        confidence = alert.get("confidence", 0)
        desc = alert.get("description", "").lower()
        
        if confidence < 45 or "routine maintenance" in desc or "scheduled test" in desc:
            return True
        return False

    def map_mitre_ttps(self, description: str) -> List[Dict[str, str]]:
        """Maps threat narrative text to MITRE ATT&CK framework IDs."""
        matched = []
        desc_lower = description.lower()

        for key, technique in self.mitre_db.items():
            if key in desc_lower:
                matched.append(technique)
                
        return matched if matched else [{"id": "T1001", "name": "Data Obfuscation"}]

    def generate_bluf(self, alert: Dict[str, Any], ttps: List[Dict[str, str]]) -> Dict[str, Any]:
        """Formats processed alert into a commander Bottom Line Up Front report."""
        priority = "CRITICAL (P1)" if alert.get("priority_score", 0) >= 70 else "HIGH (P2)"
        ttp_string = ", ".join([t["id"] for t in ttps])
        
        return {
            "alert_id": alert.get("id", "ALT-000"),
            "source": alert.get("source", "UNKNOWN"),
            "priority": priority,
            "bluf": f"BLUF: Anomaly detected at {alert.get('asset_id', 'Target Sector')}. {alert.get('description')}.",
            "mitre_ttps": ttp_string,
            "recommended_action": f"Isolate {alert.get('asset_id', 'affected node')} and deploy Response Team."
        }

    def process_pipeline(self, raw_alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Executes full pipeline: Ingest -> Filter -> Map -> BLUF."""
        processed_feed = []
        for alert in raw_alerts:
            if self.is_false_positive(alert):
                continue
            
            ttps = self.map_mitre_ttps(alert.get("description", ""))
            bluf_card = self.generate_bluf(alert, ttps)
            processed_feed.append(bluf_card)
            
        return processed_feed