from pydantic import BaseModel, Field


class Alert(BaseModel):
    alert_id: str = Field(alias="Alert ID")
    timestamp: str = Field(alias="Timestamp")
    source: str = Field(alias="Source")
    mitre_tactic: str = Field(alias="MITRE Tactic")
    mitre_technique: str = Field(alias="MITRE Technique")
    confidence: float = Field(alias="Confidence", ge=0, le=100)
    severity: float = Field(alias="Severity", ge=0, le=100)
    asset_criticality: float = Field(alias="Asset Crit", ge=0, le=5)
    priority_score: float = Field(alias="Priority Score", default=0)
    status: str = Field(alias="Status", default="Unassigned")

    class Config:
        populate_by_name = True


class AlertCreate(BaseModel):
    alert_id: str = Field(alias="Alert ID")
    timestamp: str = Field(alias="Timestamp")
    source: str = Field(alias="Source")
    mitre_tactic: str = Field(alias="MITRE Tactic")
    mitre_technique: str = Field(alias="MITRE Technique")
    confidence: float = Field(alias="Confidence", ge=0, le=100)
    severity: float = Field(alias="Severity", ge=0, le=100)
    asset_criticality: float = Field(alias="Asset Crit", ge=0, le=5)

    class Config:
        populate_by_name = True
