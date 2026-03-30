"""State models for the SOC Metrics Analyzer Agent."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

# --------------- StrEnums ---------------


class SMAStage(StrEnum):
    """Workflow stages for the SOC Metrics Analyzer."""

    COLLECT_METRICS = "collect_metrics"
    ANALYZE_PERFORMANCE = "analyze_performance"
    DETECT_BOTTLENECKS = "detect_bottlenecks"
    BENCHMARK_INDUSTRY = "benchmark_industry"
    RECOMMEND_IMPROVEMENTS = "recommend_improvements"
    REPORT = "report"


class MetricCategory(StrEnum):
    """Categories of SOC performance metrics."""

    DETECTION = "detection"
    RESPONSE = "response"
    PREVENTION = "prevention"
    COVERAGE = "coverage"
    EFFICIENCY = "efficiency"


class PerformanceTrend(StrEnum):
    """Trend direction for a tracked metric."""

    IMPROVING = "improving"
    STABLE = "stable"
    DECLINING = "declining"
    VOLATILE = "volatile"
    INSUFFICIENT_DATA = "insufficient_data"


# --------------- Domain models ---------------


class SOCMetric(BaseModel):
    """A single SOC performance metric sample."""

    metric_id: str = ""
    name: str = ""
    category: MetricCategory = MetricCategory.EFFICIENCY
    value: float = 0.0
    unit: str = ""
    timestamp: str = ""
    source: str = ""
    tags: dict[str, str] = Field(default_factory=dict)


class PerformanceAnalysis(BaseModel):
    """Analysis result for a metric category."""

    category: MetricCategory = MetricCategory.EFFICIENCY
    current_value: float = 0.0
    previous_value: float = 0.0
    trend: PerformanceTrend = PerformanceTrend.STABLE
    change_pct: float = 0.0
    assessment: str = ""
    contributing_factors: list[str] = Field(
        default_factory=list,
    )


class Bottleneck(BaseModel):
    """A detected SOC workflow bottleneck."""

    bottleneck_id: str = ""
    name: str = ""
    severity: str = "medium"
    category: MetricCategory = MetricCategory.EFFICIENCY
    description: str = ""
    impact_score: float = 0.0
    affected_metrics: list[str] = Field(default_factory=list)
    root_cause: str = ""


class IndustryBenchmark(BaseModel):
    """Industry benchmark comparison for a metric."""

    metric_name: str = ""
    category: MetricCategory = MetricCategory.EFFICIENCY
    current_value: float = 0.0
    industry_median: float = 0.0
    industry_p25: float = 0.0
    industry_p75: float = 0.0
    percentile_rank: float = 0.0
    assessment: str = ""


class ImprovementRecommendation(BaseModel):
    """Actionable recommendation to improve SOC performance."""

    recommendation_id: str = ""
    title: str = ""
    category: MetricCategory = MetricCategory.EFFICIENCY
    priority: str = "medium"
    description: str = ""
    expected_impact: str = ""
    effort: str = "medium"
    affected_bottlenecks: list[str] = Field(
        default_factory=list,
    )
    implementation_steps: list[str] = Field(
        default_factory=list,
    )


# --------------- Workflow state ---------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the analyzer workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SOCMetricsAnalyzerState(BaseModel):
    """Full state for a SOC Metrics Analyzer workflow run."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: SMAStage = SMAStage.COLLECT_METRICS
    time_range_days: int = 30
    metric_sources: list[str] = Field(
        default_factory=list,
    )

    # Collection
    raw_metrics: list[SOCMetric] = Field(
        default_factory=list,
    )

    # Analysis
    performance_analyses: list[PerformanceAnalysis] = Field(
        default_factory=list,
    )
    bottlenecks: list[Bottleneck] = Field(
        default_factory=list,
    )
    benchmarks: list[IndustryBenchmark] = Field(
        default_factory=list,
    )
    recommendations: list[ImprovementRecommendation] = Field(
        default_factory=list,
    )

    # Report
    report_summary: str = ""
    overall_score: float = 0.0

    # Workflow tracking
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
