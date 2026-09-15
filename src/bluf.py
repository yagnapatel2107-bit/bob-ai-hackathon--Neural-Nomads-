"""
bluf.py
-------
Converts scored threat clusters into BLUF (Bottom Line Up Front) format —
the lead sentence gives the verdict and required action, with supporting
detail beneath it, so a commander gets the picture in seconds.
"""

from typing import List
from correlate import ThreatCluster

MAX_SCORE_FOR_SCALE = 30  # used only to normalize a 0-100 confidence display


def _threat_level(score: float) -> str:
    if score >= 18:
        return "CRITICAL"
    if score >= 12:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def _confidence_pct(score: float) -> int:
    return min(99, round((score / MAX_SCORE_FOR_SCALE) * 100))


def _recommended_action(level: str) -> str:
    return {
        "CRITICAL": "Immediate escalation to incident commander; isolate affected assets now.",
        "HIGH": "Escalate to on-call analyst within 15 minutes; begin containment prep.",
        "MEDIUM": "Assign to analyst queue for review within shift; monitor for escalation.",
        "LOW": "Log for trend analysis; no immediate action required.",
    }[level]


def generate_bluf_for_cluster(cluster: ThreatCluster, rank: int) -> str:
    level = _threat_level(cluster.score)
    confidence = _confidence_pct(cluster.score)
    descriptions = "; ".join(sorted({a.description for a in cluster.alerts if a.description}))
    indicators = ", ".join(sorted(cluster.shared_indicators)) or "none shared"
    techniques = "; ".join(f"{t['id']} {t['name']} ({t['tactic']})" for t in cluster.techniques) or "none mapped"
    sources = ", ".join(cluster.sources)
    alert_ids = ", ".join(a.id for a in cluster.alerts)

    return f"""### Threat #{rank} — {level} (Score {cluster.score}, Confidence {confidence}%)

**BLUF:** {level.title()}-priority activity corroborated across {len(cluster.sources)} source type(s) ({sources}). {_recommended_action(level)}

- **What was observed:** {descriptions or "No description provided."}
- **Shared indicators:** {indicators}
- **MITRE ATT&CK techniques:** {techniques}
- **Corroborating alerts:** {alert_ids}
"""


def generate_report(genuine: List[ThreatCluster], false_positives: List[ThreatCluster]) -> str:
    lines = ["# Threat Assessment — BLUF Summary\n"]
    lines.append(f"**{len(genuine)}** genuine threat cluster(s) identified. "
                 f"**{len(false_positives)}** low-signal cluster(s) suppressed as likely false positives.\n")

    if not genuine:
        lines.append("No threats met the correlation threshold in this batch.\n")
    for i, cluster in enumerate(genuine, start=1):
        lines.append(generate_bluf_for_cluster(cluster, i))

    if false_positives:
        lines.append("\n---\n## Suppressed Low-Signal Alerts (for audit trail)\n")
        for c in false_positives:
            ids = ", ".join(a.id for a in c.alerts)
            lines.append(f"- Score {c.score} — alerts: {ids}")

    return "\n".join(lines)
