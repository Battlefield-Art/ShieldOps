"""State models for the Cloud IAM Analyzer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class CIAStage(StrEnum):
    """Stages in the cloud IAM analysis lifecycle."""

    COLLECT_POLICIES = "collect_policies"
    ANALYZE_PERMISSIONS = "analyze_permissions"
    DETECT_RISKS = "detect_risks"
    COMPARE_CLOUDS = "compare_clouds"
    OPTIMIZE = "optimize"
    REPORT = "report"


class CloudProvider(StrEnum):
    """Cloud provider classifications for IAM analysis."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    MULTI_CLOUD = "multi_cloud"


class IAMRiskLevel(StrEnum):
    """IAM risk level classifications."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    COMPLIANT = "compliant"


# --- Domain models ---


class IAMPolicy(BaseModel):
    """An IAM policy collected from a cloud provider."""

    policy_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    policy_name: str = ""
    policy_type: str = ""
    attached_to: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    resource_scope: list[str] = Field(default_factory=list)
    conditions: list[str] = Field(default_factory=list)
    last_used: str = ""


class PermissionAnalysis(BaseModel):
    """Analysis of IAM permissions for a principal."""

    principal_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    total_permissions: int = 0
    used_permissions: int = 0
    unused_permissions: int = 0
    overprivileged: bool = False
    admin_access: bool = False
    cross_account: bool = False
    summary: str = ""


class IAMRiskFinding(BaseModel):
    """A risk finding from IAM analysis."""

    finding_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    risk_level: IAMRiskLevel = IAMRiskLevel.MEDIUM
    category: str = ""
    principal: str = ""
    description: str = ""
    recommendation: str = ""
    affected_resources: list[str] = Field(default_factory=list)


class CloudComparison(BaseModel):
    """Cross-cloud IAM policy comparison result."""

    comparison_id: str = ""
    providers_compared: list[str] = Field(default_factory=list)
    consistency_score: float = 0.0
    gaps: list[str] = Field(default_factory=list)
    overlaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class OptimizationAction(BaseModel):
    """A recommended IAM optimization action."""

    action_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    action_type: str = ""
    target_principal: str = ""
    current_state: str = ""
    recommended_state: str = ""
    risk_reduction: float = 0.0
    effort: str = "medium"


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the IAM analyzer workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CloudIAMAnalyzerState(BaseModel):
    """Full state for a cloud IAM analyzer run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: CIAStage = CIAStage.COLLECT_POLICIES

    # Inputs
    target_providers: list[str] = Field(
        default_factory=list,
    )
    scope: dict[str, Any] = Field(default_factory=dict)
    compliance_frameworks: list[str] = Field(
        default_factory=list,
    )

    # Pipeline fields
    policies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    permission_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    cloud_comparisons: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    optimizations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_policies: int = 0
    overprivileged_count: int = 0
    critical_risks: int = 0
    optimization_count: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
