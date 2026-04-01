"""State models for the Identity Intelligence Hub Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ────────────────────────────────────────────────


class IIHStage(StrEnum):
    """Workflow stages for identity intelligence."""

    COLLECT_IDENTITY_SIGNALS = "collect_identity_signals"
    CORRELATE_IDENTITIES = "correlate_identities"
    DETECT_THREATS = "detect_threats"
    ASSESS_RISK = "assess_risk"
    RECOMMEND_ACTIONS = "recommend_actions"
    REPORT = "report"


class IdentityType(StrEnum):
    """Types of identities tracked."""

    HUMAN_USER = "human_user"
    SERVICE_ACCOUNT = "service_account"
    API_KEY = "api_key"
    OAUTH_APP = "oauth_app"
    AI_AGENT = "ai_agent"
    MCP_SERVER = "mcp_server"


class ThreatIndicator(StrEnum):
    """Identity threat indicator types."""

    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    CREDENTIAL_STUFFING = "credential_stuffing"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    DORMANT_ACTIVATION = "dormant_activation"
    EXCESSIVE_PERMISSIONS = "excessive_permissions"


# ── Domain Models ───────────────────────────────────────────


class IdentitySignal(BaseModel):
    """A collected identity signal from an IdP or IAM."""

    signal_id: str = ""
    source: str = ""
    identity_type: str = IdentityType.HUMAN_USER
    principal: str = ""
    action: str = ""
    resource: str = ""
    timestamp: str = ""
    geo_location: str = ""
    risk_indicators: list[str] = Field(
        default_factory=list,
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class CorrelatedIdentity(BaseModel):
    """A correlated identity across multiple sources."""

    correlation_id: str = ""
    identity_type: str = IdentityType.HUMAN_USER
    primary_principal: str = ""
    linked_principals: list[str] = Field(
        default_factory=list,
    )
    sources: list[str] = Field(default_factory=list)
    signal_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    confidence: float = 0.0


class ThreatDetection(BaseModel):
    """A detected identity threat."""

    detection_id: str = ""
    correlation_id: str = ""
    threat_type: str = ThreatIndicator.PRIVILEGE_ESCALATION
    severity: str = "medium"
    principal: str = ""
    evidence: list[str] = Field(default_factory=list)
    mitre_tactic: str = ""
    confidence: float = 0.0


class IdentityRiskAssessment(BaseModel):
    """Risk assessment for a correlated identity."""

    correlation_id: str = ""
    risk_score: float = 0.0
    threat_count: int = 0
    identity_type: str = IdentityType.HUMAN_USER
    exposure_level: str = "low"
    blast_radius: str = ""
    recommended_action: str = ""


class ActionRecommendation(BaseModel):
    """Recommended action for an identity threat."""

    recommendation_id: str = ""
    correlation_id: str = ""
    action_type: str = ""
    priority: str = "medium"
    description: str = ""
    automation_possible: bool = False
    estimated_impact: str = ""


# ── Reasoning Step ──────────────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the IIH workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


# ── LangGraph State ─────────────────────────────────────────


class IdentityIntelligenceHubState(BaseModel):
    """Full state for an identity intelligence workflow."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: str = IIHStage.COLLECT_IDENTITY_SIGNALS
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline outputs
    signals_collected: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    correlated_identities: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    threats_detected: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Aggregates
    total_signals: int = 0
    correlated_count: int = 0
    threat_count: int = 0
    high_risk_identities: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
