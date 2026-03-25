"""Policy Engine Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PolicyStage(StrEnum):
    COLLECT_REQUIREMENTS = "collect_requirements"
    GENERATE_POLICIES = "generate_policies"
    VALIDATE_COVERAGE = "validate_coverage"
    DETECT_DRIFT = "detect_drift"
    RECONCILE = "reconcile"
    REPORT = "report"


class PolicyType(StrEnum):
    ACCESS_CONTROL = "access_control"
    AGENT_BEHAVIOR = "agent_behavior"
    DATA_PROTECTION = "data_protection"
    NETWORK = "network"
    COMPLIANCE = "compliance"
    RESOURCE_QUOTA = "resource_quota"


class PolicyStatus(StrEnum):
    ACTIVE = "active"
    DRAFT = "draft"
    DEPRECATED = "deprecated"
    DRIFTED = "drifted"
    VIOLATED = "violated"
    PENDING_REVIEW = "pending_review"


class DriftSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityRequirement(BaseModel):
    """A security requirement from a compliance framework or custom rule set."""

    id: str = ""
    title: str = ""
    description: str = ""
    framework: str = ""
    control_id: str = ""
    priority: str = "medium"
    automated: bool = True


class GeneratedPolicy(BaseModel):
    """An OPA Rego policy generated from security requirements."""

    id: str = ""
    policy_type: PolicyType = PolicyType.ACCESS_CONTROL
    name: str = ""
    description: str = ""
    rego_code: str = ""
    requirements_covered: list[str] = Field(default_factory=list)
    status: PolicyStatus = PolicyStatus.DRAFT
    created_at: float = 0.0
    last_validated: float = 0.0


class CoverageGap(BaseModel):
    """A security requirement not covered by any generated policy."""

    id: str = ""
    requirement_id: str = ""
    requirement_title: str = ""
    gap_description: str = ""
    severity: str = "medium"
    suggested_policy: str = ""


class PolicyDrift(BaseModel):
    """A detected deviation between deployed and defined policy state."""

    id: str = ""
    policy_id: str = ""
    policy_name: str = ""
    drift_type: str = ""
    expected_state: str = ""
    actual_state: str = ""
    severity: DriftSeverity = DriftSeverity.MEDIUM
    detected_at: float = 0.0
    auto_reconcilable: bool = False


class ReconciliationAction(BaseModel):
    """An action taken to reconcile policy drift."""

    id: str = ""
    drift_id: str = ""
    action: str = ""
    description: str = ""
    applied: bool = False
    success: bool = False


class ReasoningStep(BaseModel):
    """A single reasoning step in the agent chain-of-thought."""

    step: str = ""
    detail: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyEngineState(BaseModel):
    """Full state for the Policy Engine agent workflow."""

    request_id: str = ""
    stage: PolicyStage = PolicyStage.COLLECT_REQUIREMENTS
    tenant_id: str = ""
    requirements: list[SecurityRequirement] = Field(default_factory=list)
    generated_policies: list[GeneratedPolicy] = Field(default_factory=list)
    coverage_gaps: list[CoverageGap] = Field(default_factory=list)
    policy_drifts: list[PolicyDrift] = Field(default_factory=list)
    reconciliation_actions: list[ReconciliationAction] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: int = 0
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str | None = None
