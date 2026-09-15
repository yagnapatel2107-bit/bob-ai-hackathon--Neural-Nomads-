"""
correlate.py
------------
Groups alerts across sources into threat clusters based on shared
indicators (IP, domain, hash, asset, actor) or tight time proximity, then
scores each cluster to separate genuine threats from false positives.

Scoring is intentionally transparent (sum of explainable factors) rather
than a black box, since analysts need to trust and audit the output.
"""

from dataclasses import dataclass, field
from datetime import timedelta
from typing import List, Dict
from ingest import Alert
from mitre_map import map_keywords_to_techniques

SEVERITY_WEIGHTS = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 1,
    "confirmed": 4, "probable": 3, "possible": 2, "unconfirmed": 1,
}

# Corroboration from an independent source type is worth more than another
# alert from the same source (reduces noise from one chatty sensor).
SOURCE_DIVERSITY_BONUS = 3
TIME_WINDOW = timedelta(hours=6)
FALSE_POSITIVE_THRESHOLD = 5  # clusters scoring below this are suppressed


@dataclass
class ThreatCluster:
    alerts: List[Alert] = field(default_factory=list)
    score: float = 0.0
    techniques: List[Dict[str, str]] = field(default_factory=list)

    @property
    def sources(self):
        return sorted({a.source for a in self.alerts})

    @property
    def shared_indicators(self):
        common = set()
        for a in self.alerts:
            common.update(a.indicator_set())
        return common


def _severity_score(alert: Alert) -> int:
    return SEVERITY_WEIGHTS.get(alert.severity_raw.lower(), 1)


def correlate_alerts(alerts: List[Alert]) -> List[ThreatCluster]:
    """Union-find style grouping: alerts sharing an indicator, or falling
    within TIME_WINDOW of each other with overlapping keywords, join the
    same cluster."""
    clusters: List[ThreatCluster] = []

    for alert in sorted(alerts, key=lambda a: a.timestamp):
        placed = False
        for cluster in clusters:
            shares_indicator = bool(alert.indicator_set() & cluster.shared_indicators)
            close_in_time = any(
                abs((alert.timestamp - other.timestamp)) <= TIME_WINDOW
                and set(alert.keywords) & set(other.keywords)
                for other in cluster.alerts
            )
            if shares_indicator or close_in_time:
                cluster.alerts.append(alert)
                placed = True
                break
        if not placed:
            clusters.append(ThreatCluster(alerts=[alert]))

    for cluster in clusters:
        _score_cluster(cluster)

    # Highest-priority threats first
    return sorted(clusters, key=lambda c: c.score, reverse=True)


def _score_cluster(cluster: ThreatCluster) -> None:
    severity_total = sum(_severity_score(a) for a in cluster.alerts)
    diversity_bonus = (len(cluster.sources) - 1) * SOURCE_DIVERSITY_BONUS
    corroboration_bonus = max(0, len(cluster.alerts) - 1) * 1.0

    all_keywords = [kw for a in cluster.alerts for kw in a.keywords]
    techniques = map_keywords_to_techniques(all_keywords)
    technique_bonus = len(techniques) * 1.5

    cluster.techniques = techniques
    cluster.score = round(severity_total + diversity_bonus + corroboration_bonus + technique_bonus, 1)


def split_genuine_vs_false_positive(clusters: List[ThreatCluster]):
    genuine = [c for c in clusters if c.score >= FALSE_POSITIVE_THRESHOLD]
    false_positive = [c for c in clusters if c.score < FALSE_POSITIVE_THRESHOLD]
    return genuine, false_positive
