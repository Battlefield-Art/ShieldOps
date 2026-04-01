"""State models for the Security Telemetry Aggregator Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ------------------------------------------------


class STAStage(StrEnum):
    """Workflow stages for telemetry aggregation."""

    COLLECT_TELEMETRY = "collect_telemetry"
    NORMALIZE_SIGNALS = "normalize_signals"
    CORRELATE_EVENTS = "correlate_events"
    ENRICH_CONTEXT = "enrich_context"
    ROUTE_ALERTS = "route_alerts"
    REPORT = "report"


class TelemetrySource(StrEnum):
    """Source of telemetry data."""

    AGENT = "agent"
    CONNECTOR = "connector"
    SIEM = "siem"
    EDR = "edr"
    CLOUD = "cloud"


class SignalPriority(StrEnum):
    """Priority level of a signal."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# -- Domain Models -------------------------------------------


class TelemetryRecord(BaseModel):
    """A collected telemetry record."""

    record_id: str = ""
    source: TelemetrySource = TelemetrySource.AGENT
    event_type: str = ""
    priority: SignalPriority = SignalPriority.MEDIUM
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = ""


class NormalizedSignal(BaseModel):
    """A normalized telemetry signal."""

    signal_id: str = ""
    source: TelemetrySource = TelemetrySource.AGENT
    category: str = ""
    severity: str = "medium"
    normalized_payload: dict[str, Any] = Field(default_factory=dict)


class CorrelatedEvent(BaseModel):
    """A correlated event cluster."""

    cluster_id: str = ""
    signal_ids: list[str] = Field(default_factory=list)
    correlation_score: float = 0.0
    event_type: str = ""


class EnrichedContext(BaseModel):
    """Enriched context for a correlated event."""

    cluster_id: str = ""
    threat_intel: dict[str, Any] = Field(default_factory=dict)
    asset_context: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0


class AlertRouting(BaseModel):
    """Routing decision for an alert."""

    alert_id: str = ""
    cluster_id: str = ""
    target: str = ""
    priority: SignalPriority = SignalPriority.MEDIUM
    reason: str = ""


# -- Reasoning + State ---------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityTelemetryAggregatorState(BaseModel):
    """Full state for the Security Telemetry Aggregator."""

    request_id: str = ""
    tenant_id: str = ""
    stage: STAStage = STAStage.COLLECT_TELEMETRY
    config: dict[str, Any] = Field(default_factory=dict)

    telemetry_records: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    normalized_signals: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    correlated_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    enriched_contexts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    alert_routings: list[dict[str, Any]] = Field(
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
