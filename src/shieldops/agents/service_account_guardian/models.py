"""State models for the Service Account Guardian Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class SAGStage(StrEnum):
    """Stages in the service account guardian lifecycle."""

    DISCOVER_ACCOUNTS = "discover_accounts"
    AUDIT_PERMISSIONS = "audit_permissions"
    DETECT_ORPHANS = "detect_orphans"
    ASSESS_RISK = "assess_risk"
    REMEDIATE = "remediate"
    REPORT = "report"


class AccountType(StrEnum):
    """Type of service account."""

    IAM_ROLE = "iam_role"
    SERVICE_PRINCIPAL = "service_principal"
    API_KEY = "api_key"
    OAUTH_CLIENT = "oauth_client"
    BOT_ACCOUNT = "bot_account"
    SYSTEM_ACCOUNT = "system_account"


class RiskLevel(StrEnum):
    """Risk level for a service account."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"
    UNKNOWN = "unknown"


# --- Domain models ---


class ServiceAccount(BaseModel):
    """A discovered service account."""

    account_id: str = ""
    account_name: str = ""
    account_type: AccountType = AccountType.SERVICE_PRINCIPAL
    cloud_provider: str = ""
    owner: str = ""
    created_at: datetime | None = None
    last_used: datetime | None = None
    permissions: list[str] = Field(default_factory=list)
    is_orphan: bool = False
    risk_level: RiskLevel = RiskLevel.UNKNOWN


class PermissionAudit(BaseModel):
    """Permission audit result for a service account."""

    account_id: str = ""
    excessive_permissions: list[str] = Field(
        default_factory=list,
    )
    unused_permissions: list[str] = Field(
        default_factory=list,
    )
    privilege_escalation_paths: list[str] = Field(
        default_factory=list,
    )
    last_rotation: datetime | None = None
    compliance_violations: list[str] = Field(
        default_factory=list,
    )


class OrphanDetection(BaseModel):
    """Orphaned service account detection result."""

    account_id: str = ""
    orphan_reason: str = ""
    days_inactive: int = 0
    owner_departed: bool = False
    associated_resources: list[str] = Field(
        default_factory=list,
    )
    recommended_action: str = "review"


class RiskAssessment(BaseModel):
    """Risk assessment for a service account."""

    account_id: str = ""
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    risk_score: float = 0.0
    risk_factors: list[str] = Field(default_factory=list)
    blast_radius: str = ""
    remediation_priority: int = 0


class RemediationAction(BaseModel):
    """A remediation action for a service account."""

    action_id: str = ""
    account_id: str = ""
    action_type: str = ""
    description: str = ""
    status: str = "pending"
    auto_applied: bool = False


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the guardian workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ServiceAccountGuardianState(BaseModel):
    """Full state for a service account guardian run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SAGStage = SAGStage.DISCOVER_ACCOUNTS

    # Inputs
    scan_name: str = ""
    target_providers: list[str] = Field(
        default_factory=list,
    )
    scope: dict[str, Any] = Field(default_factory=dict)
    auto_remediate: bool = False

    # Pipeline fields
    discovered_accounts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    permission_audits: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    orphan_detections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    remediation_actions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_accounts: int = 0
    orphan_count: int = 0
    high_risk_count: int = 0
    remediated_count: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
