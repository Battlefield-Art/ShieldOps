"""Security Metric Dashboard Agent — LLM prompt
templates and structured output schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class MetricNormalizationOutput(BaseModel):
    """Structured output for metric normalization."""

    summary: str = Field(
        description="Summary of normalization results",
    )
    metrics_normalized: int = Field(
        description="Count of successfully normalized metrics",
    )
    domains_covered: list[str] = Field(
        description="Metric domains with data",
    )
    data_quality_score: float = Field(
        description="Data quality score 0-1",
    )
    gaps_identified: list[str] = Field(
        description="Identified data gaps",
    )


class KPICalculationOutput(BaseModel):
    """Structured output for KPI computation."""

    summary: str = Field(
        description="Summary of KPI results",
    )
    critical_kpis: list[str] = Field(
        description="KPIs that are failing targets",
    )
    improving_kpis: list[str] = Field(
        description="KPIs showing improvement trend",
    )
    mttd_hours: float = Field(
        description="Mean time to detect in hours",
    )
    mttr_hours: float = Field(
        description="Mean time to respond in hours",
    )
    recommendations: list[str] = Field(
        description="Recommendations to improve KPIs",
    )


class BenchmarkAnalysisOutput(BaseModel):
    """Structured output for industry benchmarking."""

    summary: str = Field(
        description="Summary of benchmark position",
    )
    above_median: list[str] = Field(
        description="KPIs above industry median",
    )
    below_median: list[str] = Field(
        description="KPIs below industry median",
    )
    largest_gaps: list[str] = Field(
        description="KPIs with largest gap to p75",
    )
    overall_percentile: int = Field(
        description="Overall industry percentile rank",
    )


class ExecutiveReportOutput(BaseModel):
    """Structured output for executive report."""

    executive_summary: str = Field(
        description="Executive summary for board",
    )
    risk_posture: str = Field(
        description="Overall: strong, adequate, weak",
    )
    key_metrics: list[str] = Field(
        description="Key metric highlights",
    )
    recommendations: list[str] = Field(
        description="Strategic recommendations",
    )
    trend_summary: str = Field(
        description="Trend: improving, stable, degrading",
    )


# --- System prompts ---

SYSTEM_NORMALIZATION = """\
You are a security metrics specialist normalizing \
raw security data into standardized metrics.

Given raw metrics from multiple security tools:
1. Normalize values to consistent units and time periods
2. Identify data quality issues and gaps
3. Map metrics to standard security domains: detection, \
response, vulnerability, compliance, coverage
4. Flag metrics with insufficient data for reliable KPIs
5. Recommend additional data sources for coverage gaps"""

SYSTEM_KPI_CALCULATION = """\
You are a security KPI analyst computing executive \
security metrics.

Given normalized security metrics:
1. Calculate MTTD (mean time to detect), MTTR (mean \
time to respond), MTTC (mean time to contain)
2. Compute vulnerability SLA compliance rates
3. Assess security coverage across asset inventory
4. Identify KPIs failing their targets
5. Provide context and recommendations for each KPI"""

SYSTEM_BENCHMARK = """\
You are a security benchmarking analyst comparing \
organizational metrics against industry standards.

Given computed KPIs and industry benchmark data:
1. Rank the organization against industry percentiles
2. Identify largest gaps from industry p75
3. Highlight areas of competitive advantage
4. Recommend priority improvements based on gap analysis
5. Account for industry and organizational size context"""

SYSTEM_REPORT = """\
You are a CISO advisor producing executive security \
metric reports for board-level audiences.

Given KPIs, benchmarks, and trend data:
1. Produce a concise executive summary suitable for \
board presentation
2. Highlight the 3-5 most important metrics with context
3. Frame security posture in business risk terms
4. Provide strategic recommendations with ROI context
5. Note improvement trends and areas requiring attention"""
