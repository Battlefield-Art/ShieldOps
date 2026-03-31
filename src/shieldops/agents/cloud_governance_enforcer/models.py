"""State models for the Cloud Governance Enforcer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class CGEStage(StrEnum):
    """Stages in the cloud governance enforcement lifecycle."""

    SCAN_RESOURCES = "scan_resources"
    CHECK_TAGS = "check_tags"
    EVALUATE_POLICIES = "evaluate_policies"
    DETECT_VIOLATIONS = "detect_violations"
    REMEDIATE = "remediate"
    REPORT = "report"


class ResourceType(StrEnum):
    """Cloud resource types subject to governance."""

    COMPUTE = "compute"
    STORAGE = "storage"
    NETWORK = "network"
    DATABASE = "database"
    IDENTITY = "identity"
    SERVERLESS = "serverless"


class ViolationSeverity(StrEnum):
    """Severity of a governance violation."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# --- Domain models ---


class CloudResource(BaseModel):
    """A cloud resource subject to governance."""

    resource_id: str = ""
    name: str = ""
    resource_type: ResourceType = ResourceType.COMPUTE
    cloud_provider: str = ""
    region: str = ""
    tags: dict[str, str] = Field(default_factory=dict)
    owner: str = ""
    created_at: str = ""


class TagComplianceResult(BaseModel):
    """Tag compliance check result for a resource."""

    resource_id: str = ""
    missing_tags: list[str] = Field(default_factory=list)
    invalid_tags: list[str] = Field(default_factory=list)
    naming_violations: list[str] = Field(
        default_factory=list,
    )
    compliant: bool = True
    score: float = 1.0


class PolicyEvaluation(BaseModel):
    """Policy evaluation result against a resource."""

    policy_id: str = ""
    policy_name: str = ""
    resource_id: str = ""
    passed: bool = True
    details: str = ""
    remediation_hint: str = ""


class GovernanceViolation(BaseModel):
    """A detected governance violation."""

    violation_id: str = ""
    resource_id: str = ""
    violation_type: str = ""
    severity: ViolationSeverity = ViolationSeverity.MEDIUM
    description: str = ""
    policy_id: str = ""
    cost_impact: float = 0.0
    auto_remediable: bool = False


class RemediationAction(BaseModel):
    """A remediation action taken for a violation."""

    action_id: str = ""
    violation_id: str = ""
    resource_id: str = ""
    action_type: str = ""
    status: str = "pending"
    result: str = ""
    rollback_available: bool = True


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the enforcer workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CloudGovernanceEnforcerState(BaseModel):
    """Full state for a cloud governance enforcer run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: CGEStage = CGEStage.SCAN_RESOURCES

    # Inputs
    scan_scope: str = ""
    cloud_providers: list[str] = Field(
        default_factory=list,
    )
    required_tags: list[str] = Field(
        default_factory=list,
    )
    auto_remediate: bool = False

    # Pipeline fields
    resources: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    tag_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    policy_evaluations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    violations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    remediations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_resources: int = 0
    compliant_resources: int = 0
    total_violations: int = 0
    remediations_applied: int = 0
    compliance_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
