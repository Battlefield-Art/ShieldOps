"""State models for the Access Review Agent."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ReviewStage(StrEnum):
    """Stages in the access review campaign lifecycle."""

    COLLECT_ENTITLEMENTS = "collect_entitlements"
    ANALYZE_ACCESS = "analyze_access"
    IDENTIFY_VIOLATIONS = "identify_violations"
    GENERATE_TASKS = "generate_tasks"
    CERTIFY = "certify"
    REPORT = "report"


class ReviewDecision(StrEnum):
    """Possible decisions for an access review task."""

    APPROVE = "approve"
    REVOKE = "revoke"
    MODIFY = "modify"
    ESCALATE = "escalate"
    DEFER = "defer"


class AccessRisk(StrEnum):
    """Risk level for an entitlement."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    COMPLIANT = "compliant"


class Entitlement(BaseModel):
    """A single access entitlement granted to an identity."""

    id: str
    identity_id: str
    identity_type: str = "human"  # human, service_account, ai_agent
    resource: str = ""
    permission: str = ""
    granted_at: float = 0.0
    last_used: float = 0.0
    granted_by: str = ""
    justification: str = ""
    risk_level: AccessRisk = AccessRisk.LOW


class AccessViolation(BaseModel):
    """A detected access violation that needs review."""

    id: str
    entitlement_id: str
    violation_type: str = "excessive"  # excessive, unused, separation_of_duties, orphaned
    description: str = ""
    severity: str = "medium"
    auto_revocable: bool = False


class ReviewTask(BaseModel):
    """A review task assigned to a reviewer for certification."""

    id: str
    reviewer: str = ""
    entitlement_id: str = ""
    identity_name: str = ""
    resource: str = ""
    permission: str = ""
    recommended_decision: ReviewDecision = ReviewDecision.APPROVE
    reason: str = ""
    due_date: float = 0.0


class CertificationResult(BaseModel):
    """The result of a reviewer certifying an access review task."""

    id: str
    task_id: str = ""
    decision: ReviewDecision = ReviewDecision.APPROVE
    certified_by: str = ""
    certified_at: float = 0.0
    notes: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step: int = 0
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AccessReviewState(BaseModel):
    """Full state of an access review campaign workflow."""

    # Identity
    request_id: str = ""
    stage: ReviewStage = ReviewStage.COLLECT_ENTITLEMENTS
    tenant_id: str = ""
    campaign_name: str = ""

    # Data
    entitlements: list[Entitlement] = Field(default_factory=list)
    violations: list[AccessViolation] = Field(default_factory=list)
    review_tasks: list[ReviewTask] = Field(default_factory=list)
    certifications: list[CertificationResult] = Field(default_factory=list)

    # Metrics
    stats: dict[str, Any] = Field(default_factory=dict)

    # Workflow
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    session_start: float = 0.0
    session_duration_ms: int = 0
    error: str | None = None
