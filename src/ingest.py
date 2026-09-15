"""
ingest.py
---------
Normalizes alerts from heterogeneous defense data sources (SIEM, satellite
feeds, cyber sensors, intelligence reports) into a single common schema so
the rest of the pipeline never has to care where an alert came from.
"""

from __future__ import annotations
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any


@dataclass
class Alert:
    id: str
    source: str                # "siem" | "satellite" | "cyber_sensor" | "intel_report"
    timestamp: datetime
    description: str
    severity_raw: str          # source-native severity label
    indicators: Dict[str, List[str]] = field(default_factory=dict)  # ip, domain, hash, asset, lat_lon...
    keywords: List[str] = field(default_factory=list)               # free-text signal for MITRE mapping
    raw: Dict[str, Any] = field(default_factory=dict)                # original record, kept for traceability

    def indicator_set(self) -> set:
        """Flatten all indicator values into one set for correlation matching."""
        flat = set()
        for values in self.indicators.values():
            flat.update(values)
        return flat


def _parse_ts(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return datetime.utcnow()


def load_siem(path: Path) -> List[Alert]:
    records = json.loads(path.read_text())
    alerts = []
    for r in records:
        alerts.append(Alert(
            id=r["alert_id"],
            source="siem",
            timestamp=_parse_ts(r["timestamp"]),
            description=r.get("message", ""),
            severity_raw=r.get("severity", "unknown"),
            indicators={
                "ip": r.get("src_ip", []) + r.get("dst_ip", []),
                "hash": r.get("file_hash", []),
                "domain": r.get("domain", []),
            },
            keywords=r.get("tags", []),
            raw=r,
        ))
    return alerts


def load_satellite(path: Path) -> List[Alert]:
    records = json.loads(path.read_text())
    alerts = []
    for r in records:
        alerts.append(Alert(
            id=r["obs_id"],
            source="satellite",
            timestamp=_parse_ts(r["timestamp"]),
            description=r.get("observation", ""),
            severity_raw=r.get("confidence_band", "unknown"),
            indicators={
                "asset": [r.get("asset_id", "")] if r.get("asset_id") else [],
                "geo": [r.get("lat_lon", "")] if r.get("lat_lon") else [],
            },
            keywords=r.get("activity_tags", []),
            raw=r,
        ))
    return alerts


def load_cyber_sensor(path: Path) -> List[Alert]:
    records = json.loads(path.read_text())
    alerts = []
    for r in records:
        alerts.append(Alert(
            id=r["sensor_event_id"],
            source="cyber_sensor",
            timestamp=_parse_ts(r["timestamp"]),
            description=r.get("event_desc", ""),
            severity_raw=r.get("risk_score", "unknown"),
            indicators={
                "ip": r.get("endpoint_ip", []),
                "hash": r.get("process_hash", []),
                "domain": r.get("c2_domain", []),
            },
            keywords=r.get("behavior_tags", []),
            raw=r,
        ))
    return alerts


def load_intel_report(path: Path) -> List[Alert]:
    records = json.loads(path.read_text())
    alerts = []
    for r in records:
        alerts.append(Alert(
            id=r["report_id"],
            source="intel_report",
            timestamp=_parse_ts(r["timestamp"]),
            description=r.get("summary", ""),
            severity_raw=r.get("credibility", "unknown"),
            indicators={
                "ip": r.get("associated_ips", []),
                "domain": r.get("associated_domains", []),
                "actor": [r.get("threat_actor", "")] if r.get("threat_actor") else [],
            },
            keywords=r.get("keywords", []),
            raw=r,
        ))
    return alerts


LOADERS = {
    "siem_alerts.json": load_siem,
    "satellite_feed.json": load_satellite,
    "cyber_sensors.json": load_cyber_sensor,
    "intel_reports.json": load_intel_report,
}


def load_all(sample_dir: Path) -> List[Alert]:
    """Load and normalize every recognized feed file in sample_dir."""
    all_alerts: List[Alert] = []
    for filename, loader in LOADERS.items():
        path = sample_dir / filename
        if path.exists():
            all_alerts.extend(loader(path))
    return all_alerts
