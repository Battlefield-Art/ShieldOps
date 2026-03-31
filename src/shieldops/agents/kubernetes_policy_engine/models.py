"""State models for the Kubernetes Policy Engine Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class KPEStage(StrEnum):
    """Stages in the Kubernetes policy engine lifecycle."""

    SCAN_RESOURCES = "scan_resources"
    EVALUATE_POLICIES = "evaluate_policies"
    CHECK_STANDARDS = "check_standards"
    DETECT_VIOLATIONS = "detect_violations"
    ENFORCE = "enforce"
    REPORT = "report"


class PolicyScope(StrEnum):
    """Scope of policy evaluation."""

    NAMESPACE = "namespace"
    CLUSTER = "cluster"
    WORKLOAD = "workload"
    NETWORK = "network"
    RBAC = "rbac"
    ADMISSION = "admission"


class ViolationSeverity(StrEnum):
    """Severity of a policy violation."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"


# --- Domain models ---


class K8sResource(BaseModel):
    """A Kubernetes resource subject to policy evaluation."""

    resource_id: str = ""
    kind: str = ""
    namespace: str = ""
    name: str = ""
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    spec_summary: dict[str, Any] = Field(default_factory=dict)


class PolicyRule(BaseModel):
    """A policy rule to evaluate against K8s resources."""

    rule_id: str = ""
    policy_name: str = ""
    scope: PolicyScope = PolicyScope.WORKLOAD
    description: str = ""
    rego_query: str = ""
    severity: ViolationSeverity = ViolationSeverity.MEDIUM
    enabled: bool = True


class PolicyViolation(BaseModel):
    """A detected policy violation."""

    violation_id: str = ""
    rule_id: str = ""
    resource_kind: str = ""
    resource_name: str = ""
    namespace: str = ""
    severity: ViolationSeverity = ViolationSeverity.MEDIUM
    message: str = ""
    remediation: str = ""
    auto_fixable: bool = False


class EnforcementAction(BaseModel):
    """An enforcement action taken on a violation."""

    action_id: str = ""
    violation_id: str = ""
    action_type: str = ""
    status: str = "pending"
    details: str = ""
    applied_at: datetime | None = None


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the policy engine workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class KubernetesPolicyEngineState(BaseModel):
    """Full state for a Kubernetes policy engine run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: KPEStage = KPEStage.SCAN_RESOURCES

    # Inputs
    cluster_name: str = ""
    namespaces: list[str] = Field(default_factory=list)
    policy_scopes: list[PolicyScope] = Field(
        default_factory=list,
    )
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    resources: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    policy_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    standards_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    violations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    enforcement_actions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_resources: int = 0
    total_violations: int = 0
    critical_violations: int = 0
    compliance_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
