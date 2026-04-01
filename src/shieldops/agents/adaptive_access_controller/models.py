"""State models for the Adaptive Access Controller Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class AACStage(StrEnum):
    """Workflow stages for adaptive access control."""

    ASSESS_CONTEXT = "assess_context"
    EVALUATE_RISK = "evaluate_risk"
    ADJUST_PERMISSIONS = "adjust_permissions"
    ENFORCE_ACCESS = "enforce_access"
    AUDIT_DECISIONS = "audit_decisions"
    REPORT = "report"


class AccessDecision(StrEnum):
    """Access control decision types."""

    ALLOW = "allow"
    DENY = "deny"
    STEP_UP = "step_up"
    RESTRICT = "restrict"
    ELEVATE = "elevate"


class RiskFactor(StrEnum):
    """Risk factors for access evaluation."""

    LOCATION_ANOMALY = "location_anomaly"
    TIME_ANOMALY = "time_anomaly"
    BEHAVIOR_DEVIATION = "behavior_deviation"
    THREAT_INTEL_MATCH = "threat_intel_match"
    CREDENTIAL_COMPROMISE = "credential_compromise"


# ── Domain Models ─────────────────────────────────────


class AccessContext(BaseModel):
    """Context information for an access request."""

    identity_id: str = ""
    resource_id: str = ""
    action: str = ""
    source_ip: str = ""
    location: str = ""
    device_trust_score: float = 0.0
    session_risk: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskAssessment(BaseModel):
    """Risk assessment for an access request."""

    assessment_id: str = ""
    identity_id: str = ""
    risk_score: float = 0.0
    factors: list[str] = Field(default_factory=list)
    recommendation: str = ""
    confidence: float = 0.0


class PermissionAdjustment(BaseModel):
    """A permission adjustment decision."""

    adjustment_id: str = ""
    identity_id: str = ""
    resource_id: str = ""
    previous_access: str = ""
    new_access: str = ""
    reason: str = ""
    expires_at: str = ""


class EnforcementResult(BaseModel):
    """Result of enforcing an access decision."""

    enforcement_id: str = ""
    decision: AccessDecision = AccessDecision.DENY
    applied: bool = False
    policy_matched: str = ""
    latency_ms: int = 0


class AuditEntry(BaseModel):
    """Audit trail entry for access decisions."""

    audit_id: str = ""
    identity_id: str = ""
    resource_id: str = ""
    decision: str = ""
    risk_score: float = 0.0
    timestamp: str = ""
    justification: str = ""


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the adaptive access controller workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class AdaptiveAccessControllerState(BaseModel):
    """Full state for the Adaptive Access Controller workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: AACStage = AACStage.ASSESS_CONTEXT
    config: dict[str, Any] = Field(default_factory=dict)

    access_contexts: list[dict[str, Any]] = Field(default_factory=list)
    risk_assessments: list[dict[str, Any]] = Field(default_factory=list)
    permission_adjustments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    enforcement_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    audit_entries: list[dict[str, Any]] = Field(default_factory=list)

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
