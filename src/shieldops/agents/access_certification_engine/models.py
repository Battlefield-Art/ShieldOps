"""State models for the Access Certification Engine Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class ACEStage(StrEnum):
    """Stages in the access certification lifecycle."""

    COLLECT_ENTITLEMENTS = "collect_entitlements"
    ANALYZE_USAGE = "analyze_usage"
    IDENTIFY_EXCESS = "identify_excess"
    GENERATE_REVIEWS = "generate_reviews"
    PROCESS_DECISIONS = "process_decisions"
    REPORT = "report"


class EntitlementRisk(StrEnum):
    """Risk level of an entitlement."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"
    NONE = "none"


class ReviewDecision(StrEnum):
    """Decision for an access review item."""

    APPROVE = "approve"
    REVOKE = "revoke"
    MODIFY = "modify"
    ESCALATE = "escalate"
    DEFER = "defer"
    RUBBER_STAMP = "rubber_stamp"


# --- Domain models ---


class Entitlement(BaseModel):
    """A user entitlement collected from identity sources."""

    entitlement_id: str = ""
    user_id: str = ""
    user_name: str = ""
    resource: str = ""
    role: str = ""
    granted_at: datetime | None = None
    last_used: datetime | None = None
    usage_count_30d: int = 0


class UsageAnalysis(BaseModel):
    """Analysis of entitlement usage patterns."""

    user_id: str = ""
    total_entitlements: int = 0
    active_entitlements: int = 0
    dormant_entitlements: int = 0
    excess_permissions: int = 0
    risk_score: float = 0.0


class ExcessPermission(BaseModel):
    """An identified excess permission for review."""

    permission_id: str = ""
    user_id: str = ""
    resource: str = ""
    role: str = ""
    reason: str = ""
    risk: EntitlementRisk = EntitlementRisk.MEDIUM
    days_unused: int = 0
    sod_conflict: bool = False


class ReviewCampaign(BaseModel):
    """A generated access review campaign."""

    campaign_id: str = ""
    reviewer: str = ""
    review_items: int = 0
    due_date: datetime | None = None
    priority: str = "normal"
    rubber_stamp_risk: float = 0.0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the certification workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class AccessCertificationEngineState(BaseModel):
    """Full state for an access certification engine run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: ACEStage = ACEStage.COLLECT_ENTITLEMENTS

    # Inputs
    campaign_name: str = ""
    scope: dict[str, Any] = Field(default_factory=dict)
    identity_sources: list[str] = Field(
        default_factory=list,
    )
    review_period_days: int = 90

    # Pipeline fields
    entitlements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    usage_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    excess_permissions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    review_campaigns: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    decisions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_entitlements: int = 0
    excess_found: int = 0
    revocations_recommended: int = 0
    sod_violations: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
