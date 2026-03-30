"""IAM Policy Analyzer Agent — Pydantic state and data models."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IPAStage(StrEnum):
    COLLECT_POLICIES = "collect_policies"
    ANALYZE_PERMISSIONS = "analyze_permissions"
    DETECT_OVERPRIVILEGE = "detect_overprivilege"
    FIND_UNUSED = "find_unused"
    RECOMMEND_FIXES = "recommend_fixes"
    REPORT = "report"


class CloudProvider(StrEnum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    KUBERNETES = "kubernetes"
    OKTA = "okta"


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class IAMPolicy(BaseModel):
    """An IAM policy document from any cloud provider."""

    id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    principal_type: str = ""  # role, user, service_account, group
    principal_name: str = ""
    policy_name: str = ""
    policy_arn: str = ""
    actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    effect: str = "Allow"
    conditions: dict[str, Any] = Field(default_factory=dict)
    attached_at: float = Field(default_factory=time.time)
    is_aws_managed: bool = False


class PermissionAnalysis(BaseModel):
    """Analysis result for a single permission set."""

    id: str = ""
    policy_id: str = ""
    principal_name: str = ""
    provider: CloudProvider = CloudProvider.AWS
    total_actions: int = 0
    wildcard_actions: int = 0
    admin_actions: int = 0
    sensitive_actions: int = 0
    resource_scope: str = ""  # narrow, account-wide, wildcard
    risk_level: RiskLevel = RiskLevel.MEDIUM
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    notes: str = ""


class OverprivilegeAlert(BaseModel):
    """Alert for an over-privileged IAM principal."""

    id: str = ""
    principal_name: str = ""
    provider: CloudProvider = CloudProvider.AWS
    risk_level: RiskLevel = RiskLevel.HIGH
    overprivilege_type: str = ""  # wildcard, admin, cross-service
    excessive_actions: list[str] = Field(default_factory=list)
    blast_radius: str = ""  # single-resource, account, org
    description: str = ""
    cis_reference: str = ""


class UnusedPermission(BaseModel):
    """A permission that has not been exercised recently."""

    id: str = ""
    principal_name: str = ""
    provider: CloudProvider = CloudProvider.AWS
    action: str = ""
    last_used: str = ""  # ISO date or "never"
    days_inactive: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    recommendation: str = ""


class PolicyRecommendation(BaseModel):
    """A concrete recommendation to tighten an IAM policy."""

    id: str = ""
    principal_name: str = ""
    provider: CloudProvider = CloudProvider.AWS
    recommendation_type: str = ""  # remove, scope-down, replace
    current_policy: str = ""
    suggested_policy: str = ""
    risk_reduction: float = 0.0
    effort: str = ""  # low, medium, high
    description: str = ""
    auto_applicable: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class IAMPolicyAnalyzerState(BaseModel):
    """Main state for the IAM Policy Analyzer agent graph."""

    request_id: str = ""
    stage: IPAStage = IPAStage.COLLECT_POLICIES
    tenant_id: str = ""
    providers: list[str] = Field(default_factory=list)

    # Collected policies
    policies: list[dict[str, Any]] = Field(default_factory=list)

    # Permission analysis
    permission_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Over-privilege alerts
    overprivilege_alerts: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Unused permissions
    unused_permissions: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Recommendations
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Summary stats
    stats: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""

    # Timing
    session_start: float = Field(default_factory=time.time)
    session_duration_ms: float = 0.0

    # Error
    error: str = ""
