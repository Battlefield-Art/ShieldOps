"""State models for the Cloud Entitlement Manager Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class CEMStage(StrEnum):
    """Stages in the cloud entitlement management lifecycle."""

    DISCOVER_IDENTITIES = "discover_identities"
    ANALYZE_PERMISSIONS = "analyze_permissions"
    DETECT_EXCESS = "detect_excess"
    ASSESS_RISK = "assess_risk"
    RECOMMEND_LEAST_PRIV = "recommend_least_priv"
    REPORT = "report"


class CloudProvider(StrEnum):
    """Cloud provider for IAM analysis."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    KUBERNETES = "kubernetes"
    MULTI_CLOUD = "multi_cloud"


class IdentityType(StrEnum):
    """Type of cloud identity."""

    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    ROLE = "role"
    GROUP = "group"
    FEDERATED = "federated"
    MACHINE = "machine"


# --- Domain models ---


class CloudIdentity(BaseModel):
    """A cloud identity (user, service account, role)."""

    identity_id: str = ""
    name: str = ""
    identity_type: IdentityType = IdentityType.USER
    provider: CloudProvider = CloudProvider.AWS
    policies_attached: list[str] = Field(default_factory=list)
    last_activity: datetime | None = None
    is_active: bool = True


class PermissionAnalysis(BaseModel):
    """Analysis of permissions granted to an identity."""

    identity_id: str = ""
    total_permissions: int = 0
    used_permissions: int = 0
    unused_permissions: int = 0
    excess_ratio: float = 0.0
    high_risk_permissions: list[str] = Field(
        default_factory=list,
    )
    wildcards_found: int = 0


class ExcessPermission(BaseModel):
    """An excess permission detected on an identity."""

    identity_id: str = ""
    permission: str = ""
    last_used: datetime | None = None
    risk_level: str = "medium"
    recommendation: str = ""
    provider: CloudProvider = CloudProvider.AWS


class LeastPrivilegeRecommendation(BaseModel):
    """Least-privilege recommendation for an identity."""

    identity_id: str = ""
    current_policy: str = ""
    recommended_policy: str = ""
    permissions_removed: int = 0
    risk_reduction: float = 0.0
    provider: CloudProvider = CloudProvider.AWS


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the entitlement workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CloudEntitlementManagerState(BaseModel):
    """Full state for a cloud entitlement manager run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: CEMStage = CEMStage.DISCOVER_IDENTITIES

    # Inputs
    target_providers: list[CloudProvider] = Field(
        default_factory=list,
    )
    scope: dict[str, Any] = Field(default_factory=dict)
    scan_options: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Pipeline fields
    identities: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    permission_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    excess_permissions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_assessment: dict[str, Any] = Field(
        default_factory=dict,
    )
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_identities: int = 0
    excess_count: int = 0
    high_risk_count: int = 0
    risk_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
