"""State models for the Cloud Drift Remediator Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class CDRStage(StrEnum):
    """Workflow stages for cloud drift remediation."""

    SCAN_BASELINE = "scan_baseline"
    DETECT_DRIFT = "detect_drift"
    CLASSIFY_RISK = "classify_risk"
    PLAN_REMEDIATION = "plan_remediation"
    EXECUTE_FIX = "execute_fix"
    REPORT = "report"


class DriftType(StrEnum):
    """Types of configuration drift detected."""

    SECURITY_GROUP = "security_group"
    IAM_POLICY = "iam_policy"
    NETWORK_ACL = "network_acl"
    STORAGE_CONFIG = "storage_config"
    COMPUTE_CONFIG = "compute_config"
    DNS_RECORD = "dns_record"
    ENCRYPTION = "encryption"


class DriftRisk(StrEnum):
    """Risk classification for detected drift."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# ── Domain Models ─────────────────────────────────────


class BaselineResource(BaseModel):
    """A resource from the IaC baseline."""

    resource_id: str = ""
    resource_type: str = ""
    provider: str = ""
    region: str = ""
    iac_path: str = ""
    expected_config: dict[str, Any] = Field(default_factory=dict)
    tags: dict[str, str] = Field(default_factory=dict)


class DetectedDrift(BaseModel):
    """A detected configuration drift."""

    drift_id: str = ""
    resource_id: str = ""
    drift_type: DriftType = DriftType.SECURITY_GROUP
    field: str = ""
    expected_value: str = ""
    actual_value: str = ""
    detected_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class DriftClassification(BaseModel):
    """Risk classification for a detected drift."""

    drift_id: str = ""
    risk: DriftRisk = DriftRisk.MEDIUM
    security_impact: str = ""
    compliance_impact: str = ""
    auto_remediable: bool = False
    reasoning: str = ""


class RemediationPlan(BaseModel):
    """Remediation plan for a classified drift."""

    plan_id: str = ""
    drift_id: str = ""
    action: str = ""
    rollback_safe: bool = True
    requires_approval: bool = False
    estimated_impact: str = "low"
    iac_patch: str = ""
    description: str = ""


class ExecutionResult(BaseModel):
    """Result of executing a remediation plan."""

    plan_id: str = ""
    success: bool = False
    applied_at: datetime | None = None
    rollback_available: bool = True
    verification: str = ""
    description: str = ""


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the remediator workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CloudDriftRemediatorState(BaseModel):
    """Full state for the Cloud Drift Remediator."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: CDRStage = CDRStage.SCAN_BASELINE
    scan_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Baseline
    baseline_resources: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    resource_count: int = 0

    # Drift detection
    detected_drifts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    drift_count: int = 0

    # Classification
    drift_classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    critical_drift_count: int = 0

    # Remediation
    remediation_plans: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Execution
    execution_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
