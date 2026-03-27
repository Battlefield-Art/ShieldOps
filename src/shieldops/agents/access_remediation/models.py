"""State models for the Access Remediation Agent."""

from __future__ import annotations

from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class AccessStage(StrEnum):
    """Stages of the access remediation workflow."""

    AUDIT_ACCESS = "audit_access"
    IDENTIFY_EXCESS = "identify_excess"
    PLAN_REMEDIATION = "plan_remediation"
    EXECUTE_CHANGES = "execute_changes"
    VERIFY_ACCESS = "verify_access"
    REPORT = "report"


class AccessIssue(StrEnum):
    """Types of access issues."""

    STALE_ACCESS = "stale_access"
    OVER_PRIVILEGED = "over_privileged"
    DORMANT_ACCOUNT = "dormant_account"
    SHARED_CREDENTIAL = "shared_credential"
    ORPHANED_PERMISSION = "orphaned_permission"
    EXCESSIVE_SCOPE = "excessive_scope"


class ActionType(StrEnum):
    """Actions the agent can take on access issues."""

    REVOKE = "revoke"
    RESTRICT = "restrict"
    DISABLE = "disable"
    ROTATE = "rotate"
    NOTIFY_OWNER = "notify_owner"


class AccessAudit(BaseModel):
    """Result of auditing a single account's access."""

    id: str = Field(default_factory=lambda: f"aud-{uuid4().hex[:12]}")
    account_id: str
    account_type: str = "user"
    provider: str = "aws"
    last_login_days: int = 0
    permission_count: int = 0
    mfa_enabled: bool = True
    has_admin: bool = False
    owner_email: str = ""


class ExcessAccess(BaseModel):
    """A detected excess access issue."""

    id: str = Field(default_factory=lambda: f"exc-{uuid4().hex[:12]}")
    audit_id: str
    account_id: str
    issue_type: AccessIssue
    severity: str = "high"
    description: str = ""
    permissions_affected: list[str] = Field(default_factory=list)
    grace_period_hours: int = 72


class RemediationPlan(BaseModel):
    """Plan to remediate an access issue."""

    id: str = Field(default_factory=lambda: f"rpl-{uuid4().hex[:12]}")
    excess_id: str
    account_id: str
    action: ActionType
    description: str = ""
    owner_notified: bool = False
    approval_required: bool = False
    grace_expires_at: float = 0.0


class AccessChange(BaseModel):
    """Record of an executed access change."""

    id: str = Field(default_factory=lambda: f"ach-{uuid4().hex[:12]}")
    plan_id: str
    account_id: str
    action: ActionType
    success: bool = False
    error_message: str = ""
    executed_at: float = 0.0
    rollback_info: str = ""


class AccessVerification(BaseModel):
    """Verification that access change was applied."""

    id: str = Field(default_factory=lambda: f"avr-{uuid4().hex[:12]}")
    change_id: str
    account_id: str
    verified: bool = False
    access_still_exists: bool = False
    details: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class AccessRemediationState(BaseModel):
    """Full state of the access remediation workflow."""

    # Input
    tenant_id: str = ""
    request_id: str = Field(default_factory=lambda: f"req-{uuid4().hex[:12]}")
    target_provider: str = "aws"

    # Pipeline
    accounts_audited: list[AccessAudit] = Field(default_factory=list)
    excess_found: list[ExcessAccess] = Field(default_factory=list)
    changes_planned: list[RemediationPlan] = Field(default_factory=list)
    changes_executed: list[AccessChange] = Field(default_factory=list)
    changes_verified: list[AccessVerification] = Field(default_factory=list)

    # Counters
    accounts_remediated: int = 0

    # Report
    report_summary: str = ""

    # Metadata
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_stage: str = "init"
    error: str = ""
    duration_ms: int = 0
