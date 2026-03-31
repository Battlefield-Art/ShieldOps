"""State models for the Policy Compliance Enforcer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class PCEStage(StrEnum):
    """Stages in the policy compliance enforcement lifecycle."""

    LOAD_POLICIES = "load_policies"
    EVALUATE_REQUEST = "evaluate_request"
    CHECK_COMPLIANCE = "check_compliance"
    ENFORCE_DECISION = "enforce_decision"
    AUDIT_LOG = "audit_log"
    REPORT = "report"


class EnforcementAction(StrEnum):
    """Actions the enforcer can take."""

    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    REQUIRE_APPROVAL = "require_approval"
    QUARANTINE = "quarantine"
    EXEMPT = "exempt"


class ComplianceFramework(StrEnum):
    """Compliance frameworks supported."""

    SOC2 = "soc2"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    FEDRAMP = "fedramp"
    NIST_CSF = "nist_csf"


# --- Domain models ---


class PolicyDefinition(BaseModel):
    """A loaded policy definition for enforcement."""

    policy_id: str = ""
    name: str = ""
    framework: ComplianceFramework = ComplianceFramework.SOC2
    severity: str = "medium"
    rule_count: int = 0
    opa_module: str = ""
    enabled: bool = True


class EvaluationResult(BaseModel):
    """Result of evaluating a request against policies."""

    evaluation_id: str = ""
    request_type: str = ""
    resource: str = ""
    policies_checked: int = 0
    violations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    warnings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    compliant: bool = True


class ComplianceCheck(BaseModel):
    """Detailed compliance check result."""

    check_id: str = ""
    framework: ComplianceFramework = ComplianceFramework.SOC2
    control_id: str = ""
    status: str = "pass"
    evidence: str = ""
    remediation: str = ""


class EnforcementDecision(BaseModel):
    """A policy enforcement decision."""

    decision_id: str = ""
    action: EnforcementAction = EnforcementAction.ALLOW
    reason: str = ""
    policy_ids: list[str] = Field(default_factory=list)
    exemption_id: str = ""
    expires_at: datetime | None = None


class AuditEntry(BaseModel):
    """An immutable audit log entry."""

    entry_id: str = ""
    timestamp: datetime | None = None
    request_type: str = ""
    resource: str = ""
    action: EnforcementAction = EnforcementAction.ALLOW
    policy_ids: list[str] = Field(default_factory=list)
    actor: str = ""
    tenant_id: str = ""


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the enforcer workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class PolicyComplianceEnforcerState(BaseModel):
    """Full state for a policy compliance enforcer run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: PCEStage = PCEStage.LOAD_POLICIES

    # Inputs
    request_type: str = ""
    resource: str = ""
    actor: str = ""
    context: dict[str, Any] = Field(default_factory=dict)
    frameworks: list[str] = Field(default_factory=list)

    # Pipeline fields
    policies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    evaluations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    compliance_checks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    decisions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    audit_entries: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    compliant: bool = True
    violation_count: int = 0
    enforcement_action: str = "allow"
    exemptions_applied: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
