"""Security Metric Dashboard Agent — Pydantic state
and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SMDStage(StrEnum):
    """Stages in the security metrics lifecycle."""

    COLLECT_METRICS = "collect_metrics"
    NORMALIZE = "normalize"
    CALCULATE_KPIS = "calculate_kpis"
    BENCHMARK = "benchmark"
    BUILD_DASHBOARD = "build_dashboard"
    REPORT = "report"


class MetricDomain(StrEnum):
    """Security metric domains for aggregation."""

    DETECTION = "detection"
    RESPONSE = "response"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    COVERAGE = "coverage"
    OPERATIONAL = "operational"


class ReportAudience(StrEnum):
    """Target audience for security reports."""

    EXECUTIVE = "executive"
    BOARD = "board"
    TECHNICAL = "technical"
    COMPLIANCE_TEAM = "compliance_team"
    SOC_ANALYST = "soc_analyst"
    CISO = "ciso"


class RawMetric(BaseModel):
    """A raw security metric from any source."""

    metric_id: str = ""
    source: str = ""
    domain: MetricDomain = MetricDomain.DETECTION
    name: str = ""
    value: float = 0.0
    unit: str = ""
    timestamp: float = 0.0
    tags: dict[str, str] = Field(default_factory=dict)


class NormalizedMetric(BaseModel):
    """A normalized metric ready for KPI calculation."""

    metric_id: str = ""
    domain: MetricDomain = MetricDomain.DETECTION
    name: str = ""
    normalized_value: float = 0.0
    original_value: float = 0.0
    unit: str = ""
    period: str = ""


class KPIResult(BaseModel):
    """A computed security KPI."""

    kpi_id: str = ""
    name: str = ""
    value: float = 0.0
    target: float = 0.0
    status: str = ""
    trend: str = ""
    domain: MetricDomain = MetricDomain.DETECTION
    period: str = ""


class BenchmarkResult(BaseModel):
    """Industry benchmark comparison result."""

    kpi_name: str = ""
    org_value: float = 0.0
    industry_median: float = 0.0
    industry_p75: float = 0.0
    percentile_rank: int = 0
    gap: float = 0.0


class ReasoningStep(BaseModel):
    """Audit trail entry for the metrics workflow."""

    step_number: int = 0
    action: str = ""
    input_summary: str = ""
    output_summary: str = ""
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityMetricDashboardState(BaseModel):
    """Full state for a security metrics run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SMDStage = SMDStage.COLLECT_METRICS

    # Pipeline fields
    raw_metrics: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    normalized_metrics: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    kpis: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    benchmarks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    dashboard: dict[str, Any] = Field(
        default_factory=dict,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    kpi_count: int = 0
    failing_kpis: list[str] = Field(
        default_factory=list,
    )
    coverage_gaps: list[str] = Field(
        default_factory=list,
    )

    # Workflow tracking
    session_start: float = 0.0
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
