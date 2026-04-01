"""State models for the Cross-Cloud Posture Manager Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class CCPMStage(StrEnum):
    """Workflow stages for cross-cloud posture management."""

    SCAN_POSTURE = "scan_posture"
    COMPARE_BASELINES = "compare_baselines"
    DETECT_DRIFT = "detect_drift"
    ASSESS_COMPLIANCE = "assess_compliance"
    PLAN_REMEDIATION = "plan_remediation"
    REPORT = "report"


class CloudProvider(StrEnum):
    """Cloud providers supported for posture management."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    MULTI = "multi"


class DriftSeverity(StrEnum):
    """Severity levels for configuration drift."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ── Domain Models ─────────────────────────────────────


class PostureFinding(BaseModel):
    """A posture finding from a cloud provider scan."""

    finding_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    resource_type: str = ""
    resource_id: str = ""
    region: str = ""
    status: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class BaselineComparison(BaseModel):
    """Comparison of current posture against baseline."""

    comparison_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    baseline_version: str = ""
    matches: int = 0
    deviations: int = 0
    new_resources: int = 0
    removed_resources: int = 0


class DriftDetection(BaseModel):
    """A detected configuration drift."""

    drift_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    resource_id: str = ""
    field: str = ""
    expected_value: str = ""
    actual_value: str = ""
    severity: DriftSeverity = DriftSeverity.MEDIUM
    detected_at: str = ""


class ComplianceGap(BaseModel):
    """A compliance gap identified during assessment."""

    gap_id: str = ""
    framework: str = ""
    control_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    description: str = ""
    severity: DriftSeverity = DriftSeverity.MEDIUM
    affected_resources: list[str] = Field(default_factory=list)


class RemediationPlan(BaseModel):
    """A remediation plan for posture findings and drift."""

    plan_id: str = ""
    drift_ids: list[str] = Field(default_factory=list)
    gap_ids: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    priority: str = ""
    automated: bool = False
    estimated_effort_hours: float = 0.0


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the posture management workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CrossCloudPostureManagerState(BaseModel):
    """Full state for the Cross-Cloud Posture Manager workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CCPMStage = CCPMStage.SCAN_POSTURE
    config: dict[str, Any] = Field(default_factory=dict)

    findings: list[dict[str, Any]] = Field(default_factory=list)
    comparisons: list[dict[str, Any]] = Field(default_factory=list)
    drifts: list[dict[str, Any]] = Field(default_factory=list)
    compliance_gaps: list[dict[str, Any]] = Field(default_factory=list)
    remediation_plans: list[dict[str, Any]] = Field(default_factory=list)

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
