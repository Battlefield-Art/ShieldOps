"""State models for the Security Signal Router Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class SSRStage(StrEnum):
    """Workflow stages for security signal routing."""

    INGEST_SIGNALS = "ingest_signals"
    CLASSIFY_SIGNALS = "classify_signals"
    EVALUATE_ROUTING = "evaluate_routing"
    DISPATCH_SIGNALS = "dispatch_signals"
    TRACK_OUTCOMES = "track_outcomes"
    REPORT = "report"


class SignalCategory(StrEnum):
    """Category of a security signal."""

    THREAT = "threat"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    ANOMALY = "anomaly"
    INCIDENT = "incident"


class RoutingStrategy(StrEnum):
    """Strategy used to route signals."""

    ROUND_ROBIN = "round_robin"
    PRIORITY_BASED = "priority_based"
    CAPABILITY_MATCH = "capability_match"
    LOAD_BALANCED = "load_balanced"
    BROADCAST = "broadcast"


# ── Domain Models ─────────────────────────────────────


class SecuritySignal(BaseModel):
    """An ingested security signal."""

    signal_id: str = ""
    source: str = ""
    category: SignalCategory = SignalCategory.ANOMALY
    severity: str = "medium"
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = ""


class ClassifiedSignal(BaseModel):
    """A signal after classification."""

    signal_id: str = ""
    category: SignalCategory = SignalCategory.ANOMALY
    confidence: float = 0.0
    priority: int = 0
    tags: list[str] = Field(default_factory=list)


class RoutingDecision(BaseModel):
    """A routing decision for a signal."""

    signal_id: str = ""
    target_agent: str = ""
    strategy: RoutingStrategy = RoutingStrategy.PRIORITY_BASED
    reason: str = ""


class DispatchResult(BaseModel):
    """Result of dispatching a signal."""

    signal_id: str = ""
    target_agent: str = ""
    dispatched: bool = False
    latency_ms: int = 0


class OutcomeRecord(BaseModel):
    """Outcome tracking for a dispatched signal."""

    signal_id: str = ""
    target_agent: str = ""
    resolved: bool = False
    resolution_time_ms: int = 0
    feedback: str = ""


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the signal router workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecuritySignalRouterState(BaseModel):
    """Full state for the Security Signal Router workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SSRStage = SSRStage.INGEST_SIGNALS
    config: dict[str, Any] = Field(default_factory=dict)

    signals: list[dict[str, Any]] = Field(default_factory=list)
    classified_signals: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    routing_decisions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    dispatch_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    outcome_records: list[dict[str, Any]] = Field(
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
