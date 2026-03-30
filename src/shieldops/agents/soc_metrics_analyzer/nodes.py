"""Node implementations for the SOC Metrics Analyzer Agent."""

from __future__ import annotations

import json as _json
from typing import Any

import structlog

from shieldops.agents.soc_metrics_analyzer.models import (
    Bottleneck,
    ImprovementRecommendation,
    IndustryBenchmark,
    MetricCategory,
    PerformanceAnalysis,
    PerformanceTrend,
    ReasoningStep,
    SMAStage,
    SOCMetric,
    SOCMetricsAnalyzerState,
)
from shieldops.agents.soc_metrics_analyzer.prompts import (
    SYSTEM_BENCHMARK_COMPARISON,
    SYSTEM_BOTTLENECK_DETECTION,
    SYSTEM_PERFORMANCE_ASSESSMENT,
    SYSTEM_RECOMMENDATIONS,
    SYSTEM_REPORT_SUMMARY,
    BenchmarkAnalysisOutput,
    BottleneckDetectionOutput,
    PerformanceAssessmentOutput,
    RecommendationOutput,
    ReportSummaryOutput,
)
from shieldops.agents.soc_metrics_analyzer.tools import (
    SOCMetricsAnalyzerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SOCMetricsAnalyzerToolkit | None = None


def set_toolkit(toolkit: SOCMetricsAnalyzerToolkit) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SOCMetricsAnalyzerToolkit:
    if _toolkit is None:
        return SOCMetricsAnalyzerToolkit()
    return _toolkit


async def collect_metrics(
    state: SOCMetricsAnalyzerState,
) -> dict[str, Any]:
    """Collect SOC metrics from all configured sources."""
    toolkit = _get_toolkit()

    all_metrics: list[SOCMetric] = []
    days = state.time_range_days

    try:
        det = await toolkit.collect_detection_metrics(days)
        for m in det:
            all_metrics.append(SOCMetric(**m))
    except Exception as exc:
        logger.warning("sma.collect_detection_failed", error=str(exc))

    try:
        resp = await toolkit.collect_response_metrics(days)
        for m in resp:
            all_metrics.append(SOCMetric(**m))
    except Exception as exc:
        logger.warning("sma.collect_response_failed", error=str(exc))

    try:
        eff = await toolkit.collect_efficiency_metrics(days)
        for m in eff:
            all_metrics.append(SOCMetric(**m))
    except Exception as exc:
        logger.warning("sma.collect_efficiency_failed", error=str(exc))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_metrics",
        input_summary=(f"Collecting metrics over {days} days"),
        output_summary=(f"Collected {len(all_metrics)} metrics"),
        tool_used="metric_collectors",
    )

    return {
        "raw_metrics": all_metrics,
        "stage": SMAStage.ANALYZE_PERFORMANCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_metrics",
    }


def _determine_trend(
    history: list[dict[str, Any]],
) -> PerformanceTrend:
    """Compute trend from historical data points."""
    if len(history) < 3:
        return PerformanceTrend.INSUFFICIENT_DATA
    values = [h.get("value", 0.0) for h in history]
    diffs = [values[i + 1] - values[i] for i in range(len(values) - 1)]
    pos = sum(1 for d in diffs if d > 0)
    neg = sum(1 for d in diffs if d < 0)
    spread = max(values) - min(values)
    mean = sum(values) / len(values) if values else 1.0
    cv = spread / abs(mean) if mean else 0.0
    if cv > 0.5:
        return PerformanceTrend.VOLATILE
    if pos > neg * 2:
        return PerformanceTrend.IMPROVING
    if neg > pos * 2:
        return PerformanceTrend.DECLINING
    return PerformanceTrend.STABLE


async def analyze_performance(
    state: SOCMetricsAnalyzerState,
) -> dict[str, Any]:
    """Analyze performance across metric categories."""
    toolkit = _get_toolkit()

    categories = {m.category for m in state.raw_metrics}
    analyses: list[PerformanceAnalysis] = []

    for cat in categories:
        cat_metrics = [m for m in state.raw_metrics if m.category == cat]
        if not cat_metrics:
            continue
        avg_val = sum(m.value for m in cat_metrics) / len(
            cat_metrics,
        )
        # Get history for trend
        first_name = cat_metrics[0].name
        history = await toolkit.get_historical_metrics(
            first_name,
            periods=6,
        )
        trend = _determine_trend(history)
        prev_val = history[-2]["value"] if len(history) >= 2 else avg_val
        change = ((avg_val - prev_val) / abs(prev_val) * 100.0) if prev_val else 0.0
        analyses.append(
            PerformanceAnalysis(
                category=cat,
                current_value=round(avg_val, 2),
                previous_value=round(prev_val, 2),
                trend=trend,
                change_pct=round(change, 2),
            ),
        )

    # LLM enrichment
    try:
        ctx = _json.dumps(
            {
                "metrics": [
                    {
                        "name": m.name,
                        "category": m.category.value,
                        "value": m.value,
                        "unit": m.unit,
                    }
                    for m in state.raw_metrics
                ],
                "analyses": [
                    {
                        "category": a.category.value,
                        "current": a.current_value,
                        "previous": a.previous_value,
                        "trend": a.trend.value,
                        "change_pct": a.change_pct,
                    }
                    for a in analyses
                ],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PERFORMANCE_ASSESSMENT,
            user_prompt=f"SOC metrics:\n{ctx}",
            schema=PerformanceAssessmentOutput,
        )
        # Merge LLM assessments into analyses
        for llm_a in getattr(llm_result, "assessments", []):
            cat_val = llm_a.get("category", "")
            for analysis in analyses:
                if analysis.category.value == cat_val:
                    analysis.assessment = llm_a.get(
                        "assessment",
                        "",
                    )
                    factors = llm_a.get("factors", "")
                    if factors:
                        analysis.contributing_factors = [f.strip() for f in factors.split(",")]
        logger.info(
            "llm_enhanced",
            node="analyze_performance",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_performance",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_performance",
        input_summary=(
            f"Analyzing {len(state.raw_metrics)} metrics across {len(categories)} categories"
        ),
        output_summary=(f"Produced {len(analyses)} category analyses"),
        tool_used="performance_analyzer",
    )

    return {
        "performance_analyses": analyses,
        "stage": SMAStage.DETECT_BOTTLENECKS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_performance",
    }


async def detect_bottlenecks(
    state: SOCMetricsAnalyzerState,
) -> dict[str, Any]:
    """Detect SOC workflow bottlenecks from analyses."""
    bottlenecks: list[Bottleneck] = []

    # Rule-based detection
    for m in state.raw_metrics:
        if m.name == "false_positive_rate" and m.value > 50.0:
            bottlenecks.append(
                Bottleneck(
                    bottleneck_id=f"bn-{m.metric_id}",
                    name="High false positive rate",
                    severity="high",
                    category=MetricCategory.DETECTION,
                    description=(f"False positive rate at {m.value}% exceeds 50% threshold"),
                    impact_score=min(1.0, m.value / 100.0),
                    affected_metrics=[
                        "false_positive_rate",
                        "analyst_utilization_pct",
                    ],
                    root_cause="Detection rule tuning needed",
                ),
            )
        if m.name == "analyst_utilization_pct" and m.value > 90.0:
            bottlenecks.append(
                Bottleneck(
                    bottleneck_id=f"bn-{m.metric_id}",
                    name="Analyst burnout risk",
                    severity="critical",
                    category=MetricCategory.EFFICIENCY,
                    description=(f"Analyst utilization at {m.value}% — burnout risk"),
                    impact_score=0.95,
                    affected_metrics=[
                        "analyst_utilization_pct",
                        "mttr_hours",
                        "escalation_rate_pct",
                    ],
                    root_cause=("Insufficient staffing or automation"),
                ),
            )
        if m.name == "alert_volume_daily" and m.value > 10000:
            bottlenecks.append(
                Bottleneck(
                    bottleneck_id=f"bn-{m.metric_id}",
                    name="Alert volume overload",
                    severity="high",
                    category=MetricCategory.DETECTION,
                    description=(f"Daily alert volume at {int(m.value)} exceeds capacity"),
                    impact_score=0.85,
                    affected_metrics=[
                        "alert_volume_daily",
                        "mean_triage_minutes",
                    ],
                    root_cause=("Noisy detection rules or missing deduplication"),
                ),
            )

    # LLM enrichment
    try:
        ctx = _json.dumps(
            {
                "analyses": [a.model_dump() for a in state.performance_analyses],
                "metrics": [
                    {
                        "name": m.name,
                        "value": m.value,
                        "unit": m.unit,
                    }
                    for m in state.raw_metrics
                ],
                "rule_bottlenecks": [b.model_dump() for b in bottlenecks],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_BOTTLENECK_DETECTION,
            user_prompt=f"SOC performance data:\n{ctx}",
            schema=BottleneckDetectionOutput,
        )
        for llm_b in getattr(
            llm_result,
            "bottlenecks",
            [],
        ):
            from uuid import uuid4

            bn = Bottleneck(
                bottleneck_id=f"bn-{uuid4().hex[:8]}",
                name=llm_b.get("name", ""),
                severity=llm_b.get("severity", "medium"),
                description=llm_b.get("description", ""),
                impact_score=float(
                    llm_b.get("impact_score", 0.5),
                ),
                root_cause=llm_b.get("root_cause", ""),
            )
            # Avoid duplicates by name
            if not any(b.name == bn.name for b in bottlenecks):
                bottlenecks.append(bn)
        logger.info(
            "llm_enhanced",
            node="detect_bottlenecks",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_bottlenecks",
        )

    # Sort by impact
    bottlenecks.sort(
        key=lambda b: b.impact_score,
        reverse=True,
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_bottlenecks",
        input_summary=(f"Scanning {len(state.performance_analyses)} analyses for bottlenecks"),
        output_summary=(f"Detected {len(bottlenecks)} bottlenecks"),
        tool_used="bottleneck_detector",
    )

    return {
        "bottlenecks": bottlenecks,
        "stage": SMAStage.BENCHMARK_INDUSTRY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_bottlenecks",
    }


async def benchmark_industry(
    state: SOCMetricsAnalyzerState,
) -> dict[str, Any]:
    """Compare SOC metrics against industry benchmarks."""
    toolkit = _get_toolkit()
    benchmarks: list[IndustryBenchmark] = []

    benchmark_metrics = [
        "mttd_hours",
        "mttr_hours",
        "false_positive_rate",
        "alert_volume_daily",
        "analyst_utilization_pct",
        "detection_coverage_pct",
        "escalation_rate_pct",
        "automation_rate_pct",
    ]

    for metric_name in benchmark_metrics:
        matching = [m for m in state.raw_metrics if m.name == metric_name]
        if not matching:
            continue
        value = matching[0].value
        bench = await toolkit.get_industry_benchmarks(
            metric_name,
        )
        pctile = await toolkit.compute_percentile(
            metric_name,
            value,
        )
        benchmarks.append(
            IndustryBenchmark(
                metric_name=metric_name,
                category=matching[0].category,
                current_value=value,
                industry_median=bench.get("median", 0.0),
                industry_p25=bench.get("p25", 0.0),
                industry_p75=bench.get("p75", 0.0),
                percentile_rank=pctile,
            ),
        )

    # LLM enrichment
    try:
        ctx = _json.dumps(
            [b.model_dump() for b in benchmarks],
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_BENCHMARK_COMPARISON,
            user_prompt=f"Benchmark data:\n{ctx}",
            schema=BenchmarkAnalysisOutput,
        )
        for llm_ba in getattr(
            llm_result,
            "benchmark_assessments",
            [],
        ):
            name = llm_ba.get("metric_name", "")
            for b in benchmarks:
                if b.metric_name == name:
                    b.assessment = llm_ba.get(
                        "assessment",
                        "",
                    )
        logger.info(
            "llm_enhanced",
            node="benchmark_industry",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="benchmark_industry",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="benchmark_industry",
        input_summary=(f"Benchmarking {len(benchmarks)} metrics against industry data"),
        output_summary=(f"Completed {len(benchmarks)} benchmark comparisons"),
        tool_used="benchmark_engine",
    )

    return {
        "benchmarks": benchmarks,
        "stage": SMAStage.RECOMMEND_IMPROVEMENTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "benchmark_industry",
    }


async def recommend_improvements(
    state: SOCMetricsAnalyzerState,
) -> dict[str, Any]:
    """Generate improvement recommendations."""
    recs: list[ImprovementRecommendation] = []

    # Rule-based recommendations from bottlenecks
    for bn in state.bottlenecks:
        from uuid import uuid4

        if "false positive" in bn.name.lower():
            recs.append(
                ImprovementRecommendation(
                    recommendation_id=(f"rec-{uuid4().hex[:8]}"),
                    title="Tune detection rules",
                    category=MetricCategory.DETECTION,
                    priority="high",
                    description=(
                        "Review and tune top-noise detection rules to reduce false positive rate"
                    ),
                    expected_impact=("Reduce FP rate by 20-30%"),
                    effort="medium",
                    affected_bottlenecks=[bn.bottleneck_id],
                    implementation_steps=[
                        "Identify top 20 noisy rules",
                        "Baseline each rule FP rate",
                        "Adjust thresholds and filters",
                        "Validate over 7-day period",
                    ],
                ),
            )
        if "burnout" in bn.name.lower():
            recs.append(
                ImprovementRecommendation(
                    recommendation_id=(f"rec-{uuid4().hex[:8]}"),
                    title="Increase SOC automation",
                    category=MetricCategory.EFFICIENCY,
                    priority="critical",
                    description=(
                        "Deploy SOAR playbooks for "
                        "repetitive triage tasks to "
                        "reduce analyst workload"
                    ),
                    expected_impact=("Reduce utilization by 15-25%"),
                    effort="high",
                    affected_bottlenecks=[bn.bottleneck_id],
                    implementation_steps=[
                        "Audit top 10 manual workflows",
                        "Design SOAR playbooks",
                        "Implement auto-enrichment",
                        "Deploy auto-close for known FPs",
                        "Measure utilization delta",
                    ],
                ),
            )

    # LLM-generated recommendations
    try:
        ctx = _json.dumps(
            {
                "bottlenecks": [b.model_dump() for b in state.bottlenecks],
                "benchmarks": [b.model_dump() for b in state.benchmarks],
                "analyses": [a.model_dump() for a in state.performance_analyses],
                "existing_recs": [r.title for r in recs],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RECOMMENDATIONS,
            user_prompt=(f"SOC analysis data:\n{ctx}"),
            schema=RecommendationOutput,
        )
        for llm_r in getattr(
            llm_result,
            "recommendations",
            [],
        ):
            from uuid import uuid4

            title = llm_r.get("title", "")
            if any(r.title == title for r in recs):
                continue
            steps_raw = llm_r.get("steps", "")
            steps = (
                [s.strip() for s in steps_raw.split(",")]
                if isinstance(steps_raw, str)
                else list(steps_raw)
            )
            recs.append(
                ImprovementRecommendation(
                    recommendation_id=(f"rec-{uuid4().hex[:8]}"),
                    title=title,
                    priority=llm_r.get(
                        "priority",
                        "medium",
                    ),
                    description=llm_r.get(
                        "description",
                        "",
                    ),
                    expected_impact=llm_r.get(
                        "expected_impact",
                        "",
                    ),
                    effort=llm_r.get("effort", "medium"),
                    implementation_steps=steps,
                ),
            )
        logger.info(
            "llm_enhanced",
            node="recommend_improvements",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend_improvements",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="recommend_improvements",
        input_summary=(f"Generating recommendations from {len(state.bottlenecks)} bottlenecks"),
        output_summary=(f"Produced {len(recs)} recommendations"),
        tool_used="recommendation_engine",
    )

    return {
        "recommendations": recs,
        "stage": SMAStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_improvements",
    }


async def generate_report(
    state: SOCMetricsAnalyzerState,
) -> dict[str, Any]:
    """Generate the final SOC performance report."""
    toolkit = _get_toolkit()

    # Compute overall score from benchmarks
    if state.benchmarks:
        avg_pctile = sum(b.percentile_rank for b in state.benchmarks) / len(state.benchmarks)
    else:
        avg_pctile = 50.0
    overall_score = round(avg_pctile, 1)

    summary = (
        f"SOC Performance Report | Score: {overall_score}/100 | "
        f"Metrics: {len(state.raw_metrics)} | "
        f"Bottlenecks: {len(state.bottlenecks)} | "
        f"Recommendations: {len(state.recommendations)}"
    )

    # LLM enrichment for executive summary
    try:
        ctx = _json.dumps(
            {
                "overall_score": overall_score,
                "analyses": [a.model_dump() for a in state.performance_analyses],
                "bottlenecks": [b.model_dump() for b in state.bottlenecks[:5]],
                "benchmarks": [b.model_dump() for b in state.benchmarks],
                "recommendations": [r.model_dump() for r in state.recommendations[:5]],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT_SUMMARY,
            user_prompt=f"Report data:\n{ctx}",
            schema=ReportSummaryOutput,
        )
        if hasattr(llm_result, "executive_summary"):
            summary = llm_result.executive_summary
        if hasattr(llm_result, "overall_score"):
            overall_score = round(
                llm_result.overall_score,
                1,
            )
        logger.info(
            "llm_enhanced",
            node="generate_report",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Persist results
    await toolkit.store_analysis(
        {
            "request_id": state.request_id,
            "tenant_id": state.tenant_id,
            "overall_score": overall_score,
            "metric_count": len(state.raw_metrics),
            "bottleneck_count": len(state.bottlenecks),
            "recommendation_count": len(
                state.recommendations,
            ),
        },
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary="Compiling final report",
        output_summary=(f"Report complete — score {overall_score}"),
        tool_used="report_generator",
    )

    return {
        "report_summary": summary,
        "overall_score": overall_score,
        "stage": SMAStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
