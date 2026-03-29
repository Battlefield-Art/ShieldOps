"""Security Metrics Collector Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MetricsStage(StrEnum):
    DEFINE_METRICS = "define_metrics"
    COLLECT_DATA = "collect_data"
    CALCULATE_KPIS = "calculate_kpis"
    BENCHMARK_PERFORMANCE = "benchmark_performance"
    GENERATE_DASHBOARD = "generate_dashboard"
    REPORT = "report"


class MetricCategory(StrEnum):
    DETECTION = "detection"
    RESPONSE = "response"
    PREVENTION = "prevention"
    COMPLIANCE = "compliance"
    RISK = "risk"
    OPERATIONAL = "operational"


class PerformanceTrend(StrEnum):
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class SecurityMetricsCollectorState(BaseModel):
    request_id: str = ""
    stage: MetricsStage = MetricsStage.DEFINE_METRICS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
