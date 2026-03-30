"""Performance Baseline Engine Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PBEStage(StrEnum):
    COLLECT_METRICS = "collect_metrics"
    ESTABLISH_BASELINES = "establish_baselines"
    DETECT_REGRESSIONS = "detect_regressions"
    ANALYZE_TRENDS = "analyze_trends"
    ALERT_DEVIATIONS = "alert_deviations"
    REPORT = "report"


class BaselineMetric(StrEnum):
    LATENCY_P50 = "latency_p50"
    LATENCY_P99 = "latency_p99"
    ERROR_RATE = "error_rate"
    THROUGHPUT = "throughput"
    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"


class DeviationSeverity(StrEnum):
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    NORMAL = "normal"
    IMPROVED = "improved"


class PerformanceBaselineEngineState(BaseModel):
    request_id: str = ""
    stage: PBEStage = PBEStage.COLLECT_METRICS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
