"""SOC Metrics Dashboard Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MetricsStage(StrEnum):
    COLLECT_DATA = "collect_data"
    COMPUTE_KPIS = "compute_kpis"
    IDENTIFY_TRENDS = "identify_trends"
    BENCHMARK = "benchmark"
    RECOMMEND = "recommend"
    REPORT = "report"


class MetricCategory(StrEnum):
    DETECTION = "detection"
    RESPONSE = "response"
    RESOLUTION = "resolution"
    COVERAGE = "coverage"
    EFFICIENCY = "efficiency"
    QUALITY = "quality"


class TrendDirection(StrEnum):
    IMPROVING = "improving"
    STABLE = "stable"
    DECLINING = "declining"
    VOLATILE = "volatile"
    INSUFFICIENT_DATA = "insufficient_data"


class SocMetricsDashboardState(BaseModel):
    request_id: str = ""
    stage: MetricsStage = MetricsStage.COLLECT_DATA
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
