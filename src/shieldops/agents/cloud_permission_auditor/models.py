"""Cloud Permission Auditor Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CPAStage(StrEnum):
    COLLECT_PERMISSIONS = "collect_permissions"
    ANALYZE_SCOPE = "analyze_scope"
    DETECT_VIOLATIONS = "detect_violations"
    MAP_CROSS_ACCOUNT = "map_cross_account"
    GENERATE_FIXES = "generate_fixes"
    REPORT = "report"


class ViolationType(StrEnum):
    OVERPRIVILEGED = "overprivileged"
    UNUSED_PERMISSION = "unused_permission"
    CROSS_ACCOUNT = "cross_account"
    DORMANT_CREDENTIAL = "dormant_credential"
    WILDCARD_ACCESS = "wildcard_access"
    ESCALATION_PATH = "escalation_path"


class PermissionScope(StrEnum):
    ORGANIZATION = "organization"
    ACCOUNT = "account"
    PROJECT = "project"
    RESOURCE = "resource"
    SERVICE = "service"


class CloudPermission(BaseModel):
    """A single IAM permission entry from a cloud provider."""

    id: str = ""
    principal: str = ""
    principal_type: str = ""
    provider: str = ""
    account_id: str = ""
    policy_name: str = ""
    actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    scope: PermissionScope = PermissionScope.ACCOUNT
    last_used_days: int = 0
    is_wildcard: bool = False
    tags: dict[str, str] = Field(default_factory=dict)


class ScopeAnalysis(BaseModel):
    """Analysis of permission scope for a principal."""

    principal: str = ""
    provider: str = ""
    total_permissions: int = 0
    used_permissions: int = 0
    unused_pct: float = 0.0
    scope: PermissionScope = PermissionScope.ACCOUNT
    risk_score: float = 0.0
    wildcard_count: int = 0
    notes: list[str] = Field(default_factory=list)


class PermissionViolation(BaseModel):
    """A detected permission violation."""

    id: str = ""
    principal: str = ""
    provider: str = ""
    violation_type: ViolationType = ViolationType.OVERPRIVILEGED
    severity: str = "medium"
    description: str = ""
    affected_actions: list[str] = Field(default_factory=list)
    affected_resources: list[str] = Field(default_factory=list)
    risk_score: float = 0.0


class CrossAccountAccess(BaseModel):
    """A cross-account access mapping."""

    id: str = ""
    source_account: str = ""
    target_account: str = ""
    principal: str = ""
    provider: str = ""
    trust_type: str = ""
    actions: list[str] = Field(default_factory=list)
    is_external: bool = False
    last_used_days: int = 0
    risk_score: float = 0.0


class PermissionFix(BaseModel):
    """A recommended fix for a permission violation."""

    id: str = ""
    violation_id: str = ""
    principal: str = ""
    action: str = ""
    description: str = ""
    policy_before: str = ""
    policy_after: str = ""
    auto_applicable: bool = False
    risk: str = "low"


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudPermissionAuditorState(BaseModel):
    """Main state for the Cloud Permission Auditor agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CPAStage = CPAStage.COLLECT_PERMISSIONS

    permissions: list[CloudPermission] = Field(
        default_factory=list,
    )
    scope_analyses: list[ScopeAnalysis] = Field(
        default_factory=list,
    )
    violations: list[PermissionViolation] = Field(
        default_factory=list,
    )
    cross_account_access: list[CrossAccountAccess] = Field(
        default_factory=list,
    )
    fixes: list[PermissionFix] = Field(
        default_factory=list,
    )

    report: str = ""
    total_principals: int = 0
    total_violations: int = 0
    critical_violations: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
