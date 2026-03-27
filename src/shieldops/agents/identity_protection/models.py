"""State models for the Identity Protection Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ProtectionStage(StrEnum):
    """Stages in the identity protection workflow."""

    COLLECT_SIGNALS = "collect_identity_signals"
    DETECT_THREATS = "detect_threats"
    ANALYZE_PATTERNS = "analyze_attack_patterns"
    RESPOND = "respond_to_threats"
    VERIFY = "verify_containment"
    REPORT = "report"


class IdentityThreat(StrEnum):
    """Types of identity-based threats detected."""

    CREDENTIAL_THEFT = "credential_theft"
    BRUTE_FORCE = "brute_force"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    MFA_BYPASS = "mfa_bypass"
    TOKEN_THEFT = "token_theft"  # noqa: S105
    SESSION_HIJACK = "session_hijack"


class IdentitySource(StrEnum):
    """Supported identity providers for signal collection."""

    OKTA = "okta"
    ENTRA_ID = "entra_id"
    AWS_IAM = "aws_iam"
    GCP_IAM = "gcp_iam"
    K8S_RBAC = "k8s_rbac"
    AI_AGENT_REGISTRY = "ai_agent_registry"


class IdentitySignal(BaseModel):
    """A single identity event signal from any provider."""

    signal_id: str
    source: str = ""
    identity_id: str = ""
    identity_type: str = "human"
    event_type: str = ""
    ip_address: str = ""
    geo_location: str = ""
    user_agent: str = ""
    timestamp: datetime | None = None
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ThreatDetection(BaseModel):
    """A detected identity threat with evidence."""

    detection_id: str
    threat_type: str = ""
    identity_id: str = ""
    source: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: str = "medium"
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    related_signals: list[str] = Field(default_factory=list)
    detected_at: datetime | None = None


class AttackPattern(BaseModel):
    """An identified attack chain across identity signals."""

    pattern_id: str
    pattern_type: str = ""
    kill_chain_stage: str = ""
    identities_involved: list[str] = Field(default_factory=list)
    providers_affected: list[str] = Field(default_factory=list)
    detection_ids: list[str] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    description: str = ""


class ThreatResponse(BaseModel):
    """An automated response action taken against a threat."""

    response_id: str
    action_type: str = ""
    target_identity: str = ""
    target_provider: str = ""
    status: str = "pending"
    details: dict[str, Any] = Field(default_factory=dict)
    executed_at: datetime | None = None
    rollback_available: bool = True


class ContainmentVerification(BaseModel):
    """Verification that a threat response was effective."""

    verification_id: str
    response_id: str = ""
    identity_id: str = ""
    is_contained: bool = False
    residual_risk: float = Field(default=0.0, ge=0.0, le=100.0)
    verification_checks: list[str] = Field(default_factory=list)
    verified_at: datetime | None = None


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class IdentityProtectionState(BaseModel):
    """Full state of an identity protection workflow."""

    # Input
    tenant_id: str = ""
    providers: list[str] = Field(
        default_factory=lambda: [
            "okta",
            "entra_id",
            "aws_iam",
            "gcp_iam",
            "k8s_rbac",
            "ai_agent_registry",
        ]
    )
    time_window_minutes: int = 60
    scope: dict[str, Any] = Field(default_factory=dict)

    # Pipeline state
    signals_collected: list[IdentitySignal] = Field(
        default_factory=list,
    )
    threats_detected: list[ThreatDetection] = Field(
        default_factory=list,
    )
    attack_patterns: list[AttackPattern] = Field(
        default_factory=list,
    )
    responses_executed: list[ThreatResponse] = Field(
        default_factory=list,
    )
    containment_verified: list[ContainmentVerification] = Field(
        default_factory=list,
    )
    identities_protected: list[str] = Field(
        default_factory=list,
    )

    # Workflow
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
