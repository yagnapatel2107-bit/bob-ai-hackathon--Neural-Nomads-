from typing import Dict


def calculate_priority_score(
    confidence: float,
    severity: float,
    asset_criticality: float
) -> float:
    """
    Calculate alert priority score.

    Formula:
    (Confidence * 0.4)
    + (Severity * 0.3)
    + ((Asset Criticality * 20) * 0.3)
    """

    score = (
        (confidence * 0.4)
        + (severity * 0.3)
        + ((asset_criticality * 20) * 0.3)
    )

    return round(score, 2)


def determine_status(priority_score: float) -> str:
    """Determine alert status from priority score."""

    if priority_score >= 75:
        return "Triaged"

    return "Unassigned"


def process_alert(alert: Dict) -> Dict:
    """Process an alert and add priority score and status."""

    score = calculate_priority_score(
        alert["Confidence"],
        alert["Severity"],
        alert["Asset Crit"]
    )

    alert["Priority Score"] = score
    alert["Status"] = determine_status(score)

    return alert
