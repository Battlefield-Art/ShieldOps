"""State models for the SLA Violation Detector Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SVDStage(StrEnum):
    """Stages in the SLA violation detection workflow."""

    COLLECT_METRICS = "collect_metrics"
    EVALUATE_THRESHOLDS = "evaluate_thresholds"
    DETECT_VIOLATIONS = "detect_violations"
    CALCULATE_IMPACT = "calculate_impact"
    NOTIFY_OWNERS = "notify_owners"
    REPORT = "report"


class SLAType(StrEnum):
    """SLA type classification."""

    AVAILABILITY = "availability"
    LATENCY = "latency"
    ERROR_RATE = "error_rate"
    THROUGHPUT = "throughput"
    RESOLUTION_TIME = "resolution_time"
    RESPONSE_TIME = "response_time"


class ViolationSeverity(StrEnum):
    """SLA violation severity levels."""

    BREACH = "breach"
    WARNING = "warning"
    AT_RISK = "at_risk"
    HEALTHY = "healthy"
    EXCEEDED = "exceeded"


class SLAViolationDetectorState(BaseModel):
    """Full state for the SLA violation detector."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SVDStage = SVDStage.COLLECT_METRICS

    services: list[str] = Field(
        default_factory=list,
    )
    time_window_hours: int = 24

    collected_metrics: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    threshold_evaluations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    violations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    impact_calculations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    notifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    stats: dict[str, Any] = Field(
        default_factory=dict,
    )
    reasoning_chain: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    current_step: str = ""
    error: str = ""
