"""Node implementations for the Security Metric
Dashboard Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.agents.security_metric_dashboard.models import (
    ReasoningStep,
    SecurityMetricDashboardState,
    SMDStage,
)
from shieldops.agents.security_metric_dashboard.prompts import (
    SYSTEM_BENCHMARK,
    SYSTEM_KPI_CALCULATION,
    SYSTEM_NORMALIZATION,
    SYSTEM_REPORT,
    BenchmarkAnalysisOutput,
    ExecutiveReportOutput,
    KPICalculationOutput,
    MetricNormalizationOutput,
)
from shieldops.agents.security_metric_dashboard.tools import (
    SecurityMetricDashboardToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityMetricDashboardToolkit | None = None


def set_toolkit(
    toolkit: SecurityMetricDashboardToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityMetricDashboardToolkit:
    if _toolkit is None:
        return SecurityMetricDashboardToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: float,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((time.time() - start) * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: collect_metrics
# ------------------------------------------------------------------


async def collect_metrics(
    state: SecurityMetricDashboardState,
) -> dict[str, Any]:
    """Collect raw security metrics from all sources."""
    start = time.time()
    toolkit = _get_toolkit()

    results = await toolkit.collect_metrics(
        tenant_id=state.tenant_id,
    )

    step = _step(
        state.reasoning_chain,
        "collect_metrics",
        f"Tenant: {state.tenant_id}",
        f"Collected {len(results)} raw metrics",
        start,
        "metric_collector",
    )

    return {
        "raw_metrics": results,
        "stage": SMDStage.COLLECT_METRICS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_metrics",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: normalize_metrics
# ------------------------------------------------------------------


async def normalize_metrics(
    state: SecurityMetricDashboardState,
) -> dict[str, Any]:
    """Normalize raw metrics to consistent units."""
    start = time.time()
    toolkit = _get_toolkit()

    normalized = await toolkit.normalize_metrics(
        raw_metrics=state.raw_metrics,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "raw_count": len(state.raw_metrics),
                "normalized_count": len(normalized),
                "sample": normalized[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_NORMALIZATION,
            user_prompt=(f"Normalize security metrics:\n{ctx}"),
            schema=MetricNormalizationOutput,
        )
        logger.info(
            "llm_enhanced",
            node="normalize_metrics",
            quality=llm_out.data_quality_score,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="normalize_metrics",
        )

    step = _step(
        state.reasoning_chain,
        "normalize_metrics",
        f"Normalizing {len(state.raw_metrics)} metrics",
        f"Normalized {len(normalized)} metrics",
        start,
        "normalizer",
    )

    return {
        "normalized_metrics": normalized,
        "stage": SMDStage.NORMALIZE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "normalize_metrics",
    }


# ------------------------------------------------------------------
# Node: calculate_kpis
# ------------------------------------------------------------------


async def calculate_kpis(
    state: SecurityMetricDashboardState,
) -> dict[str, Any]:
    """Calculate security KPIs from normalized metrics."""
    start = time.time()
    toolkit = _get_toolkit()

    kpis = await toolkit.calculate_kpis(
        normalized=state.normalized_metrics,
    )

    failing = [k["name"] for k in kpis if k.get("status") == "failing"]

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "kpi_count": len(kpis),
                "kpis": kpis,
                "failing": failing,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_KPI_CALCULATION,
            user_prompt=f"Calculate KPIs:\n{ctx}",
            schema=KPICalculationOutput,
        )
        logger.info(
            "llm_enhanced",
            node="calculate_kpis",
            critical=len(
                llm_out.critical_kpis  # type: ignore[union-attr]
            ),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="calculate_kpis",
        )

    step = _step(
        state.reasoning_chain,
        "calculate_kpis",
        (f"Computing from {len(state.normalized_metrics)} metrics"),
        f"{len(kpis)} KPIs, {len(failing)} failing",
        start,
        "kpi_calculator",
    )

    return {
        "kpis": kpis,
        "kpi_count": len(kpis),
        "failing_kpis": failing,
        "stage": SMDStage.CALCULATE_KPIS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "calculate_kpis",
    }


# ------------------------------------------------------------------
# Node: benchmark_industry
# ------------------------------------------------------------------


async def benchmark_industry(
    state: SecurityMetricDashboardState,
) -> dict[str, Any]:
    """Benchmark KPIs against industry standards."""
    start = time.time()
    toolkit = _get_toolkit()

    benchmarks = await toolkit.benchmark_industry(
        kpis=state.kpis,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "benchmarks": benchmarks,
                "kpis": state.kpis,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_BENCHMARK,
            user_prompt=f"Benchmark analysis:\n{ctx}",
            schema=BenchmarkAnalysisOutput,
        )
        logger.info(
            "llm_enhanced",
            node="benchmark_industry",
            percentile=llm_out.overall_percentile,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="benchmark_industry",
        )

    step = _step(
        state.reasoning_chain,
        "benchmark_industry",
        f"Benchmarking {len(state.kpis)} KPIs",
        f"Compared against {len(benchmarks)} benchmarks",
        start,
        "benchmark_engine",
    )

    return {
        "benchmarks": benchmarks,
        "stage": SMDStage.BENCHMARK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "benchmark_industry",
    }


# ------------------------------------------------------------------
# Node: build_dashboard
# ------------------------------------------------------------------


async def build_dashboard(
    state: SecurityMetricDashboardState,
) -> dict[str, Any]:
    """Build dashboard data payload."""
    start = time.time()
    toolkit = _get_toolkit()

    dashboard = await toolkit.build_dashboard(
        kpis=state.kpis,
        benchmarks=state.benchmarks,
    )

    gaps = [
        d
        for d in ["endpoint", "network", "cloud", "identity"]
        if not any(k.get("domain") == d for k in state.kpis)
    ]

    step = _step(
        state.reasoning_chain,
        "build_dashboard",
        f"Building from {state.kpi_count} KPIs",
        "Dashboard payload generated",
        start,
        "dashboard_builder",
    )

    return {
        "dashboard": dashboard,
        "coverage_gaps": gaps,
        "stage": SMDStage.BUILD_DASHBOARD,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "build_dashboard",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecurityMetricDashboardState,
) -> dict[str, Any]:
    """Generate executive security metrics report."""
    start = time.time()
    _toolkit_ref = _get_toolkit()

    duration_ms = int((time.time() - state.session_start) * 1000)

    report: dict[str, Any] = {
        "kpi_count": state.kpi_count,
        "failing_kpis": state.failing_kpis,
        "coverage_gaps": state.coverage_gaps,
        "benchmarks": state.benchmarks,
        "duration_ms": duration_ms,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "kpis": state.kpis,
                "benchmarks": state.benchmarks,
                "failing": state.failing_kpis,
                "gaps": state.coverage_gaps,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate executive report:\n{ctx}"),
            schema=ExecutiveReportOutput,
        )
        if isinstance(llm_out, ExecutiveReportOutput):
            report.update(
                {
                    "executive_summary": (llm_out.executive_summary),
                    "risk_posture": llm_out.risk_posture,
                    "key_metrics": llm_out.key_metrics,
                    "recommendations": (llm_out.recommendations),
                    "trend_summary": llm_out.trend_summary,
                }
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

    await _toolkit_ref.record_metric(
        "smd.run_completed",
        1.0,
        {"tenant_id": state.tenant_id},
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.kpi_count} KPIs",
        "Executive report generated",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": SMDStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
