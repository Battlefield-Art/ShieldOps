"""Physical Access Monitor Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class AccessPatternResult(BaseModel):
    """Structured output from LLM-assisted pattern analysis."""

    summary: str = Field(
        description="Brief summary of access patterns",
    )
    tailgating_risk: int = Field(
        description="Number of potential tailgating events",
    )
    after_hours_count: int = Field(
        description="After-hours access attempts",
    )
    risk_level: str = Field(
        description="Overall risk: low, medium, high, critical",
    )
    recommended_actions: list[str] = Field(
        description="Priority actions for access anomalies",
    )


class AnomalyDetectionResult(BaseModel):
    """Structured output from LLM-assisted anomaly detection."""

    summary: str = Field(
        description="Brief summary of detected anomalies",
    )
    anomalous_persons: int = Field(
        description="People with anomalous access patterns",
    )
    threat_level: str = Field(
        description="Threat level: low, medium, high, critical",
    )
    insider_threat_indicators: list[str] = Field(
        description="Indicators of potential insider threats",
    )
    immediate_actions: list[str] = Field(
        description="Actions to take immediately",
    )


SYSTEM_ACCESS_PATTERN = (
    "You are a physical security analyst reviewing "
    "badge swipe and access control data.\n"
    "Given the access event data:\n"
    "1. Identify tailgating patterns where multiple "
    "entries occur on a single badge swipe\n"
    "2. Flag after-hours access to restricted areas\n"
    "3. Detect badge sharing or cloning indicators\n"
    "4. Identify unusual zone traversal sequences\n"
    "5. Recommend policy enforcement actions"
)

SYSTEM_ANOMALY_DETECTION = (
    "You are a physical security threat analyst.\n"
    "Given detected access anomalies:\n"
    "1. Correlate anomalies to identify coordinated "
    "social engineering or insider threats\n"
    "2. Assess risk of unauthorized data center access\n"
    "3. Identify badge cloning or relay attack patterns\n"
    "4. Map threats to physical security kill chains\n"
    "5. Prioritize alerts by asset criticality"
)
