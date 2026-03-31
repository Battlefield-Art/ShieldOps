"""State models for the Third Party Risk Monitor Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class TPRMStage(StrEnum):
    """Stages in the third-party risk monitoring lifecycle."""

    INVENTORY_VENDORS = "inventory_vendors"
    ASSESS_POSTURE = "assess_posture"
    MONITOR_CHANGES = "monitor_changes"
    EVALUATE_RISK = "evaluate_risk"
    GENERATE_ALERTS = "generate_alerts"
    REPORT = "report"


class VendorTier(StrEnum):
    """Vendor criticality tier classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"
    UNCLASSIFIED = "unclassified"


class RiskDomain(StrEnum):
    """Domain of third-party risk assessment."""

    SECURITY = "security"
    COMPLIANCE = "compliance"
    OPERATIONAL = "operational"
    FINANCIAL = "financial"
    REPUTATIONAL = "reputational"
    DATA_PRIVACY = "data_privacy"


# --- Domain models ---


class VendorProfile(BaseModel):
    """A third-party vendor profile."""

    vendor_id: str = ""
    name: str = ""
    tier: VendorTier = VendorTier.MEDIUM
    services: list[str] = Field(default_factory=list)
    data_access: list[str] = Field(default_factory=list)
    contract_expiry: str = ""
    last_assessment: str = ""
    risk_score: float = 0.0


class PostureAssessment(BaseModel):
    """Security posture assessment for a vendor."""

    vendor_id: str = ""
    domain: RiskDomain = RiskDomain.SECURITY
    score: float = 0.0
    findings: list[str] = Field(default_factory=list)
    certifications: list[str] = Field(
        default_factory=list,
    )
    gaps: list[str] = Field(default_factory=list)
    assessed_at: datetime | None = None


class PostureChange(BaseModel):
    """A detected change in vendor posture."""

    change_id: str = ""
    vendor_id: str = ""
    change_type: str = ""
    severity: str = "low"
    description: str = ""
    detected_at: datetime | None = None
    previous_score: float = 0.0
    current_score: float = 0.0


class RiskEvaluation(BaseModel):
    """Risk evaluation result for a vendor."""

    vendor_id: str = ""
    overall_risk: float = 0.0
    risk_domains: dict[str, float] = Field(
        default_factory=dict,
    )
    breach_history: list[str] = Field(
        default_factory=list,
    )
    sla_compliance: float = 0.0
    recommendation: str = ""


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the risk monitor workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ThirdPartyRiskMonitorState(BaseModel):
    """Full state for a third-party risk monitor run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: TPRMStage = TPRMStage.INVENTORY_VENDORS

    # Inputs
    vendor_filters: dict[str, Any] = Field(
        default_factory=dict,
    )
    risk_domains: list[RiskDomain] = Field(
        default_factory=list,
    )
    monitoring_config: dict[str, Any] = Field(
        default_factory=dict,
    )
    threshold_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Pipeline fields
    vendors: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    posture_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    posture_changes: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_evaluations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    alerts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_vendors: int = 0
    high_risk_vendors: int = 0
    posture_changes_count: int = 0
    alerts_generated: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
