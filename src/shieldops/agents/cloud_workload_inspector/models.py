"""State models for the Cloud Workload Inspector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class CWIStage(StrEnum):
    """Workflow stages for cloud workload inspection."""

    DISCOVER_WORKLOADS = "discover_workloads"
    ANALYZE_CONFIG = "analyze_config"
    CHECK_COMPLIANCE = "check_compliance"
    ASSESS_RISK = "assess_risk"
    RECOMMEND = "recommend"
    REPORT = "report"


class WorkloadType(StrEnum):
    """Types of cloud workloads inspected."""

    EC2_INSTANCE = "ec2_instance"
    GCE_INSTANCE = "gce_instance"
    AZURE_VM = "azure_vm"
    CONTAINER = "container"
    LAMBDA_FUNCTION = "lambda_function"
    KUBERNETES_POD = "kubernetes_pod"
    RDS_INSTANCE = "rds_instance"


class ComplianceStatus(StrEnum):
    """Compliance check result statuses."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    UNKNOWN = "unknown"
    EXEMPT = "exempt"


# ── Domain Models ─────────────────────────────────────


class DiscoveredWorkload(BaseModel):
    """A cloud workload discovered during inspection."""

    workload_id: str = ""
    workload_type: WorkloadType = WorkloadType.EC2_INSTANCE
    name: str = ""
    region: str = ""
    cloud_provider: str = ""
    instance_type: str = ""
    is_public: bool = False
    tags: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ConfigFinding(BaseModel):
    """A configuration finding from workload analysis."""

    finding_id: str = ""
    workload_id: str = ""
    category: str = ""
    severity: str = "medium"
    description: str = ""
    current_value: str = ""
    expected_value: str = ""
    auto_fixable: bool = False


class ComplianceCheck(BaseModel):
    """A compliance check result for a workload."""

    check_id: str = ""
    workload_id: str = ""
    framework: str = ""
    control_id: str = ""
    status: ComplianceStatus = ComplianceStatus.UNKNOWN
    details: str = ""


class RiskAssessment(BaseModel):
    """Risk assessment for an inspected workload."""

    workload_id: str = ""
    risk_score: float = 0.0
    exposure_level: str = "low"
    encryption_status: str = "unknown"
    iam_risk: str = "low"
    network_risk: str = "low"
    reasoning: str = ""


class Recommendation(BaseModel):
    """Remediation recommendation for a workload."""

    rec_id: str = ""
    workload_id: str = ""
    priority: str = "medium"
    action: str = ""
    effort: str = "medium"
    risk_reduction: float = 0.0
    description: str = ""


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the inspector workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CloudWorkloadInspectorState(BaseModel):
    """Full state for the Cloud Workload Inspector workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: CWIStage = CWIStage.DISCOVER_WORKLOADS
    inspect_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Discovery
    discovered_workloads: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    public_workload_count: int = 0

    # Config analysis
    config_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    critical_finding_count: int = 0

    # Compliance
    compliance_checks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    compliance_pass_rate: float = 0.0

    # Risk
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    max_risk_score: float = 0.0

    # Recommendations
    recommendations: list[dict[str, Any]] = Field(
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
