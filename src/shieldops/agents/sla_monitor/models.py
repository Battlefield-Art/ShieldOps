"""State models for the SLA Monitor Agent LangGraph workflow."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MonitorStage(StrEnum):
    """Stages of the SLA monitoring workflow."""

    COLLECT_SLIS = "collect_slis"
    CALCULATE_SLOS = "calculate_slos"
    TRACK_ERROR_BUDGETS = "track_error_budgets"
    DETECT_BURN_RATE = "detect_burn_rate"
    ALERT = "alert"
    REPORT = "report"


class SLIType(StrEnum):
    """Types of Service Level Indicators."""

    AVAILABILITY = "availability"
    LATENCY = "latency"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"
    SATURATION = "saturation"


class BudgetStatus(StrEnum):
    """Error budget consumption status."""

    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    EXHAUSTED = "exhausted"
    EXCEEDED = "exceeded"


class SLIMetric(BaseModel):
    """A collected Service Level Indicator measurement."""

    id: str = ""
    service: str = ""
    sli_type: SLIType = SLIType.AVAILABILITY
    current_value: float = 0.0
    target_value: float = 99.9
    window_hours: int = 720
    compliant: bool = True


class SLOStatus(BaseModel):
    """Computed SLO status for a service."""

    id: str = ""
    service: str = ""
    slo_name: str = ""
    target_pct: float = 99.9
    current_pct: float = 100.0
    budget_remaining_pct: float = 100.0
    budget_status: BudgetStatus = BudgetStatus.HEALTHY
    burn_rate: float = 0.0


class BurnRateAlert(BaseModel):
    """Alert triggered by abnormal error budget burn rate."""

    id: str = ""
    service: str = ""
    slo_name: str = ""
    burn_rate_1h: float = 0.0
    burn_rate_6h: float = 0.0
    budget_exhaustion_hours: float = 0.0
    severity: str = "warning"
    recommended_action: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the SLA monitor workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SLAMonitorState(BaseModel):
    """Full state for an SLA monitor workflow run through the LangGraph workflow."""

    # Input
    tenant_id: str = ""
    services: list[str] = Field(default_factory=list)

    # Collect SLIs
    sli_metrics: list[SLIMetric] = Field(default_factory=list)

    # Calculate SLOs
    slo_statuses: list[SLOStatus] = Field(default_factory=list)

    # Error budgets
    budget_summary: dict[str, Any] = Field(default_factory=dict)

    # Burn rate detection
    burn_rate_alerts: list[BurnRateAlert] = Field(default_factory=list)
    has_alerts: bool = False

    # Alert
    alerts_sent: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str | None = None
