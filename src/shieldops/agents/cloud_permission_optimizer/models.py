"""State models for the Cloud Permission Optimizer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class CPOStage(StrEnum):
    """Stages in the cloud permission optimization lifecycle."""

    COLLECT_PERMISSIONS = "collect_permissions"
    ANALYZE_USAGE = "analyze_usage"
    DETECT_EXCESS = "detect_excess"
    CALCULATE_LEAST_PRIV = "calculate_least_priv"
    RECOMMEND = "recommend"
    REPORT = "report"


class CloudProvider(StrEnum):
    """Supported cloud providers for permission analysis."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    KUBERNETES = "kubernetes"
    MULTI_CLOUD = "multi_cloud"
    ON_PREM = "on_prem"


class PermissionRisk(StrEnum):
    """Risk level for permission grants."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    COMPLIANT = "compliant"


# --- Domain models ---


class PermissionGrant(BaseModel):
    """A permission grant attached to a principal."""

    grant_id: str = ""
    principal_arn: str = ""
    provider: CloudProvider = CloudProvider.AWS
    permission: str = ""
    resource_scope: str = ""
    last_used: datetime | None = None
    risk: PermissionRisk = PermissionRisk.LOW


class UsageRecord(BaseModel):
    """API call usage record for a permission."""

    permission: str = ""
    call_count: int = 0
    last_invoked: datetime | None = None
    source_ip: str = ""
    service: str = ""


class ExcessPermission(BaseModel):
    """An over-privileged permission detected by analysis."""

    excess_id: str = ""
    principal_arn: str = ""
    permission: str = ""
    risk: PermissionRisk = PermissionRisk.MEDIUM
    days_unused: int = 0
    recommendation: str = ""


class LeastPrivilegePolicy(BaseModel):
    """Computed least-privilege policy for a principal."""

    principal_arn: str = ""
    provider: CloudProvider = CloudProvider.AWS
    required_permissions: list[str] = Field(default_factory=list)
    removed_permissions: list[str] = Field(default_factory=list)
    policy_document: dict[str, Any] = Field(default_factory=dict)
    reduction_pct: float = 0.0


class Recommendation(BaseModel):
    """A permission right-sizing recommendation."""

    rec_id: str = ""
    principal_arn: str = ""
    action: str = ""
    risk: PermissionRisk = PermissionRisk.MEDIUM
    impact: str = ""
    auto_remediate: bool = False


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the optimizer workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CloudPermissionOptimizerState(BaseModel):
    """Full state for a cloud permission optimizer run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: CPOStage = CPOStage.COLLECT_PERMISSIONS

    # Inputs
    target_providers: list[CloudProvider] = Field(
        default_factory=list,
    )
    scope: dict[str, Any] = Field(default_factory=dict)
    lookback_days: int = 90

    # Pipeline fields
    permissions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    usage_records: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    excess_permissions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    least_privilege_policies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_permissions: int = 0
    excess_count: int = 0
    reduction_pct: float = 0.0
    risk_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
