"""State models for the Alert Correlation Agent LangGraph workflow."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CorrelationStage(StrEnum):
    """Stages of the alert correlation pipeline."""

    COLLECT_ALERTS = "collect_alerts"
    NORMALIZE = "normalize"
    CORRELATE = "correlate"
    BUILD_CHAINS = "build_chains"
    PRIORITIZE = "prioritize"
    REPORT = "report"


class CorrelationType(StrEnum):
    """Types of correlation between alerts."""

    TEMPORAL = "temporal"
    CAUSAL = "causal"
    TOPOLOGICAL = "topological"
    IDENTITY_BASED = "identity_based"
    KILL_CHAIN = "kill_chain"


class AlertPriority(StrEnum):
    """Incident priority levels."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"


class RawAlert(BaseModel):
    """An alert ingested from any source before normalization."""

    id: str = ""
    source: str = ""
    alert_type: str = ""
    severity: str = ""
    title: str = ""
    description: str = ""
    timestamp: float = 0.0
    entities: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class CorrelationCluster(BaseModel):
    """A group of correlated alerts that likely represent a single incident."""

    id: str = ""
    alert_ids: list[str] = Field(default_factory=list)
    correlation_type: CorrelationType = CorrelationType.TEMPORAL
    confidence: float = 0.0
    root_cause_hypothesis: str = ""
    kill_chain_stage: str = ""
    affected_assets: list[str] = Field(default_factory=list)


class PrioritizedIncident(BaseModel):
    """A correlation cluster promoted to a prioritized incident."""

    id: str = ""
    cluster_id: str = ""
    priority: AlertPriority = AlertPriority.P3
    title: str = ""
    narrative: str = ""
    recommended_action: str = ""
    auto_actionable: bool = False
    estimated_impact: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the alert correlation workflow."""

    step_number: int = 0
    action: str = ""
    input_summary: str = ""
    output_summary: str = ""
    duration_ms: int = 0
    tool_used: str | None = None


class AlertCorrelationState(BaseModel):
    """Full state for an alert correlation workflow run."""

    # Input
    tenant_id: str = ""
    time_window_minutes: int = 60

    # Pipeline data
    raw_alerts: list[RawAlert] = Field(default_factory=list)
    normalized_alerts: list[RawAlert] = Field(default_factory=list)
    clusters: list[CorrelationCluster] = Field(default_factory=list)
    incidents: list[PrioritizedIncident] = Field(default_factory=list)

    # Metrics
    noise_reduction_ratio: float = 0.0
    total_alerts_ingested: int = 0
    total_incidents_created: int = 0

    # Workflow tracking
    current_stage: CorrelationStage = CorrelationStage.COLLECT_ALERTS
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
    session_duration_ms: int = 0
