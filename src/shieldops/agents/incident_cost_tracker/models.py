"""State models for the Incident Cost Tracker Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class ICTStage(StrEnum):
    """Stages in the incident cost tracking lifecycle."""

    IDENTIFY_INCIDENT = "identify_incident"
    CALCULATE_DIRECT = "calculate_direct"
    ESTIMATE_INDIRECT = "estimate_indirect"
    ASSESS_REGULATORY = "assess_regulatory"
    FORECAST_TOTAL = "forecast_total"
    REPORT = "report"


class CostCategory(StrEnum):
    """Category of incident-related cost."""

    CONTAINMENT = "containment"
    REMEDIATION = "remediation"
    FORENSICS = "forensics"
    NOTIFICATION = "notification"
    LEGAL = "legal"
    REGULATORY_FINE = "regulatory_fine"
    DOWNTIME = "downtime"
    REPUTATION = "reputation"


class IncidentSeverity(StrEnum):
    """Severity classification of the incident."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNDETERMINED = "undetermined"


# --- Domain models ---


class IncidentProfile(BaseModel):
    """Profile of the security incident being costed."""

    incident_id: str = ""
    title: str = ""
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    incident_type: str = ""
    affected_systems: list[str] = Field(default_factory=list)
    records_exposed: int = 0
    downtime_hours: float = 0.0
    detected_at: datetime | None = None
    contained_at: datetime | None = None


class DirectCost(BaseModel):
    """Direct financial cost of incident response."""

    category: CostCategory = CostCategory.CONTAINMENT
    amount_usd: float = 0.0
    description: str = ""
    vendor: str = ""
    hours_spent: float = 0.0


class IndirectCost(BaseModel):
    """Indirect financial impact of the incident."""

    category: str = ""
    amount_usd: float = 0.0
    description: str = ""
    confidence: float = 0.0
    time_horizon_months: int = 12


class RegulatoryExposure(BaseModel):
    """Regulatory fine and compliance exposure."""

    regulation: str = ""
    jurisdiction: str = ""
    max_fine_usd: float = 0.0
    estimated_fine_usd: float = 0.0
    probability: float = 0.0
    notification_required: bool = False
    deadline_days: int = 72


class CostForecast(BaseModel):
    """Total cost forecast with confidence intervals."""

    total_direct_usd: float = 0.0
    total_indirect_usd: float = 0.0
    total_regulatory_usd: float = 0.0
    grand_total_usd: float = 0.0
    confidence_low_usd: float = 0.0
    confidence_high_usd: float = 0.0
    insurance_coverage_usd: float = 0.0
    net_exposure_usd: float = 0.0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the orchestrator workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class IncidentCostTrackerState(BaseModel):
    """Full state for an incident cost tracker run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: ICTStage = ICTStage.IDENTIFY_INCIDENT

    # Inputs
    incident_id: str = ""
    incident_type: str = ""
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    affected_systems: list[str] = Field(
        default_factory=list,
    )
    records_exposed: int = 0
    downtime_hours: float = 0.0
    scope: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    incident_profile: dict[str, Any] = Field(
        default_factory=dict,
    )
    direct_costs: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    indirect_costs: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    regulatory_exposure: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    forecast: dict[str, Any] = Field(
        default_factory=dict,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_direct_usd: float = 0.0
    total_indirect_usd: float = 0.0
    total_regulatory_usd: float = 0.0
    grand_total_usd: float = 0.0
    insurance_coverage_usd: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
