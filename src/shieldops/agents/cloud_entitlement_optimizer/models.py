"""State models for the Cloud Entitlement Optimizer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ------------------------------------------------


class CEOStage(StrEnum):
    """Workflow stages for entitlement optimization."""

    INVENTORY_ENTITLEMENTS = "inventory_entitlements"
    ANALYZE_USAGE = "analyze_usage"
    IDENTIFY_EXCESS = "identify_excess"
    CALCULATE_RISK = "calculate_risk"
    RECOMMEND_CHANGES = "recommend_changes"
    REPORT = "report"


class EntitlementType(StrEnum):
    """Type of cloud entitlement."""

    IAM_ROLE = "iam_role"
    SERVICE_ACCOUNT = "service_account"
    API_KEY = "api_key"
    OAUTH_TOKEN = "oauth_token"
    MANAGED_IDENTITY = "managed_identity"


class RiskLevel(StrEnum):
    """Risk level classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# -- Domain Models -------------------------------------------


class EntitlementRecord(BaseModel):
    """An inventoried entitlement."""

    entitlement_id: str = ""
    ent_type: EntitlementType = EntitlementType.IAM_ROLE
    principal: str = ""
    permissions: list[str] = Field(default_factory=list)
    cloud_provider: str = ""
    created_at: str = ""


class UsageAnalysis(BaseModel):
    """Usage analysis for an entitlement."""

    entitlement_id: str = ""
    permissions_used: int = 0
    permissions_total: int = 0
    last_used: str = ""
    usage_pct: float = 0.0


class ExcessEntitlement(BaseModel):
    """An identified excess entitlement."""

    entitlement_id: str = ""
    excess_permissions: list[str] = Field(
        default_factory=list,
    )
    excess_pct: float = 0.0
    idle_days: int = 0


class RiskAssessment(BaseModel):
    """Risk assessment for excess entitlements."""

    entitlement_id: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    risk_score: float = 0.0
    blast_radius: str = ""
    attack_vector: str = ""


class ChangeRecommendation(BaseModel):
    """Recommended entitlement change."""

    recommendation_id: str = ""
    entitlement_id: str = ""
    action: str = ""
    permissions_to_remove: list[str] = Field(
        default_factory=list,
    )
    expected_risk_reduction: float = 0.0


# -- Reasoning + State ---------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CloudEntitlementOptimizerState(BaseModel):
    """Full state for the Cloud Entitlement Optimizer."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CEOStage = CEOStage.INVENTORY_ENTITLEMENTS
    config: dict[str, Any] = Field(default_factory=dict)

    entitlements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    usage_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    excess_entitlements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
