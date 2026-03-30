"""State models for the Identity Threat Detector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ----------------------------------------------------------


class ITDStage(StrEnum):
    """Workflow stages for identity threat detection."""

    COLLECT_AUTH_EVENTS = "collect_auth_events"
    ANALYZE_BEHAVIOR = "analyze_behavior"
    DETECT_ANOMALY = "detect_anomaly"
    ASSESS_RISK = "assess_risk"
    RESPOND = "respond"
    REPORT = "report"


class IdentityThreatType(StrEnum):
    """Identity-based threat types."""

    IMPOSSIBLE_TRAVEL = "impossible_travel"
    CREDENTIAL_STUFFING = "credential_stuffing"
    MFA_BYPASS = "mfa_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ACCOUNT_TAKEOVER = "account_takeover"
    BRUTE_FORCE = "brute_force"
    LATERAL_MOVEMENT = "lateral_movement"


class RiskLevel(StrEnum):
    """Identity risk levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# -- Domain Models -----------------------------------------------------


class AuthEvent(BaseModel):
    """An authentication event."""

    event_id: str = ""
    user_id: str = ""
    event_type: str = "login"
    source_ip: str = ""
    geo_location: str = ""
    device_id: str = ""
    mfa_used: bool = False
    success: bool = True
    timestamp: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class BehaviorProfile(BaseModel):
    """User behavior profile for anomaly detection."""

    user_id: str = ""
    typical_locations: list[str] = Field(
        default_factory=list,
    )
    typical_hours: list[int] = Field(
        default_factory=list,
    )
    typical_devices: list[str] = Field(
        default_factory=list,
    )
    avg_session_duration_min: float = 0.0
    risk_baseline: float = 0.0


class IdentityAnomaly(BaseModel):
    """A detected identity anomaly."""

    anomaly_id: str = ""
    user_id: str = ""
    threat_type: IdentityThreatType = IdentityThreatType.IMPOSSIBLE_TRAVEL
    confidence: float = 0.0
    indicators: list[str] = Field(default_factory=list)
    description: str = ""


class IdentityRiskAssessment(BaseModel):
    """Risk assessment for an identity anomaly."""

    assessment_id: str = ""
    anomaly_id: str = ""
    user_id: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    risk_score: float = 0.0
    business_impact: str = "medium"
    reasoning: str = ""


class ResponseAction(BaseModel):
    """Response action for an identity threat."""

    action_id: str = ""
    anomaly_id: str = ""
    action_type: str = "alert"
    success: bool = False
    details: str = ""


# -- Reasoning + State -------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the detector workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class IdentityThreatDetectorState(BaseModel):
    """Full state for the Identity Threat Detector workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: ITDStage = ITDStage.COLLECT_AUTH_EVENTS
    detection_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Auth events
    auth_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    event_count: int = 0

    # Behavior
    behavior_profiles: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Anomalies
    anomalies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    anomaly_count: int = 0

    # Risk
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    max_risk_score: float = 0.0

    # Response
    response_actions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    responded_count: int = 0

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
