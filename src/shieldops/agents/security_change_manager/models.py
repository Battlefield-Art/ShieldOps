"""Security Change Manager Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SCMStage(StrEnum):
    RECEIVE_CHANGE = "receive_change"
    ASSESS_RISK = "assess_risk"
    CHECK_DEPENDENCIES = "check_dependencies"
    APPROVE_OR_REJECT = "approve_or_reject"
    MONITOR_ROLLOUT = "monitor_rollout"
    REPORT = "report"


class ChangeRiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"
    UNKNOWN = "unknown"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    DEFERRED = "deferred"
    AUTO_APPROVED = "auto_approved"
    ESCALATED = "escalated"


class ChangeRequest(BaseModel):
    """A single change request submitted for review."""

    id: str = ""
    title: str = ""
    description: str = ""
    submitter: str = ""
    service: str = ""
    environment: str = "staging"
    change_type: str = "standard"
    scheduled_at: str = ""
    rollback_plan: str = ""
    ticket_url: str = ""


class RiskAssessment(BaseModel):
    """Risk assessment result for a change request."""

    id: str = ""
    change_id: str = ""
    risk_level: ChangeRiskLevel = ChangeRiskLevel.MEDIUM
    risk_score: float = 0.0
    blast_radius: int = 0
    affected_services: list[str] = Field(default_factory=list)
    security_impact: str = ""
    compliance_flags: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)


class DependencyCheck(BaseModel):
    """Dependency analysis for a change request."""

    id: str = ""
    change_id: str = ""
    upstream_services: list[str] = Field(default_factory=list)
    downstream_services: list[str] = Field(default_factory=list)
    conflicting_changes: list[str] = Field(default_factory=list)
    dependency_risk: float = 0.0
    freeze_window_conflict: bool = False


class ApprovalDecision(BaseModel):
    """Approval or rejection decision for a change."""

    id: str = ""
    change_id: str = ""
    status: ApprovalStatus = ApprovalStatus.PENDING
    approver: str = ""
    reason: str = ""
    conditions: list[str] = Field(default_factory=list)
    approved_at: str = ""


class RolloutMetric(BaseModel):
    """Post-change rollout monitoring metric."""

    id: str = ""
    change_id: str = ""
    metric_name: str = ""
    baseline_value: float = 0.0
    current_value: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    rollback_recommended: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityChangeManagerState(BaseModel):
    """Main state for the Security Change Manager agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SCMStage = SCMStage.RECEIVE_CHANGE

    changes: list[ChangeRequest] = Field(
        default_factory=list,
    )
    risk_assessments: list[RiskAssessment] = Field(
        default_factory=list,
    )
    dependency_checks: list[DependencyCheck] = Field(
        default_factory=list,
    )
    approval_decisions: list[ApprovalDecision] = Field(
        default_factory=list,
    )
    rollout_metrics: list[RolloutMetric] = Field(
        default_factory=list,
    )

    report: str = ""
    total_changes_processed: int = 0
    changes_approved: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
