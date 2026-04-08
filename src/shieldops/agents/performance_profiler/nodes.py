"""Performance Profiler Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    LatencyAnalysis,
    PerformanceBottleneck,
    ProfilerStage,
    ResourceContention,
    TraceSpan,
)
from .tools import PerformanceProfilerToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: PerformanceProfilerToolkit | None = None


def _get_toolkit() -> PerformanceProfilerToolkit:
    """Get the module-level toolkit, creating a default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = PerformanceProfilerToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def collect_traces(
    state: dict[str, Any], toolkit: PerformanceProfilerToolkit
) -> dict[str, Any]:
    """Collect distributed trace spans from APM instrumentation."""
    logger.info("performance_profiler.node.collect_traces")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    spans = await toolkit.collect_trace_spans(tenant_id)
    spans_data = [s.model_dump() for s in spans]

    return {
        "stage": ProfilerStage.ANALYZE_LATENCY.value,
        "spans": spans_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(spans)} trace spans for tenant '{tenant_id}'"],
    }


async def analyze_latency(
    state: dict[str, Any], toolkit: PerformanceProfilerToolkit
) -> dict[str, Any]:
    """Compute latency percentile distributions per service endpoint."""
    logger.info("performance_profiler.node.analyze_latency")
    state = _to_dict(state)

    raw_spans = state.get("spans", [])
    spans = [TraceSpan(**s) for s in raw_spans]

    analyses = await toolkit.analyze_latency_distribution(spans)
    analyses_data = [a.model_dump() for a in analyses]

    return {
        "stage": ProfilerStage.DETECT_BOTTLENECKS.value,
        "latency_analyses": analyses_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Analyzed latency for {len(analyses)} endpoints — "
            f"worst p99: {analyses[0].p99_ms:.1f}ms"
            if analyses
            else "No endpoints to analyze"
        ],
    }


async def detect_bottlenecks(
    state: dict[str, Any], toolkit: PerformanceProfilerToolkit
) -> dict[str, Any]:
    """Detect performance bottlenecks from trace and latency data."""
    logger.info("performance_profiler.node.detect_bottlenecks")
    state = _to_dict(state)

    raw_spans = state.get("spans", [])
    spans = [TraceSpan(**s) for s in raw_spans]
    raw_analyses = state.get("latency_analyses", [])
    analyses = [LatencyAnalysis(**a) for a in raw_analyses]

    bottlenecks = await toolkit.detect_bottlenecks(spans, analyses)
    bottlenecks_data = [b.model_dump() for b in bottlenecks]

    reasoning_note = f"Detected {len(bottlenecks)} performance bottlenecks"

    # LLM enhancement: deeper bottleneck analysis
    try:
        from .prompts import SYSTEM_DETECT_BOTTLENECKS, BottleneckAnalysisResult

        context = json.dumps(
            {
                "total_spans": len(spans),
                "bottlenecks_found": len(bottlenecks),
                "bottleneck_summary": [
                    {
                        "service": b.service,
                        "type": b.bottleneck_type,
                        "impact": b.impact,
                        "latency_ms": b.avg_latency_ms,
                    }
                    for b in bottlenecks[:10]
                ],
                "latency_summary": [
                    {
                        "service": a.service,
                        "endpoint": a.endpoint,
                        "p99_ms": a.p99_ms,
                    }
                    for a in analyses[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            BottleneckAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_DETECT_BOTTLENECKS,
                user_prompt=f"Bottleneck analysis context:\n{context}",
                schema=BottleneckAnalysisResult,
            ),
        )
        logger.info("llm_enhanced", agent="performance_profiler", node="detect_bottlenecks")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="performance_profiler", node="detect_bottlenecks")

    return {
        "stage": ProfilerStage.IDENTIFY_CONTENTION.value,
        "bottlenecks": bottlenecks_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def identify_contention(
    state: dict[str, Any], toolkit: PerformanceProfilerToolkit
) -> dict[str, Any]:
    """Identify resource contention points across services."""
    logger.info("performance_profiler.node.identify_contention")
    state = _to_dict(state)

    raw_spans = state.get("spans", [])
    spans = [TraceSpan(**s) for s in raw_spans]

    contentions = await toolkit.identify_resource_contention(spans)
    contentions_data = [c.model_dump() for c in contentions]

    return {
        "stage": ProfilerStage.RECOMMEND.value,
        "contentions": contentions_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Identified {len(contentions)} resource contention points"],
    }


async def recommend(state: dict[str, Any], toolkit: PerformanceProfilerToolkit) -> dict[str, Any]:
    """Generate prioritized optimization recommendations."""
    logger.info("performance_profiler.node.recommend")
    state = _to_dict(state)

    raw_bottlenecks = state.get("bottlenecks", [])
    bottlenecks = [PerformanceBottleneck(**b) for b in raw_bottlenecks]
    raw_contentions = state.get("contentions", [])
    contentions = [ResourceContention(**c) for c in raw_contentions]

    recommendations: list[str] = []

    # Build recommendations from bottlenecks
    for b in bottlenecks:
        recommendations.append(
            f"[{b.impact.upper()}] {b.service}/{b.bottleneck_type}: "
            f"{b.optimization} (est. {b.estimated_improvement_pct:.0f}% improvement)"
        )

    # Build recommendations from contention
    for c in contentions:
        if c.severity in ("high", "critical"):
            recommendations.append(
                f"[CONTENTION] {c.service}/{c.resource}: "
                f"Resolve {c.contention_type} affecting "
                f"{', '.join(c.affected_operations[:3])}"
            )

    return {
        "stage": ProfilerStage.REPORT.value,
        "recommendations": recommendations,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Generated {len(recommendations)} optimization recommendations"],
    }


async def generate_report(
    state: dict[str, Any], toolkit: PerformanceProfilerToolkit
) -> dict[str, Any]:
    """Compile final performance profiling report."""
    logger.info("performance_profiler.node.generate_report")
    state = _to_dict(state)

    raw_bottlenecks = state.get("bottlenecks", [])
    raw_contentions = state.get("contentions", [])
    raw_analyses = state.get("latency_analyses", [])
    recommendations = state.get("recommendations", [])

    total_bottlenecks = len(raw_bottlenecks)
    critical_count = sum(1 for b in raw_bottlenecks if b.get("impact") == "critical")
    high_count = sum(1 for b in raw_bottlenecks if b.get("impact") == "high")

    report = {
        "tenant_id": state.get("tenant_id", ""),
        "total_spans_analyzed": len(state.get("spans", [])),
        "endpoints_profiled": len(raw_analyses),
        "bottlenecks_detected": total_bottlenecks,
        "critical_bottlenecks": critical_count,
        "high_bottlenecks": high_count,
        "contention_points": len(raw_contentions),
        "recommendations_count": len(recommendations),
        "top_recommendations": recommendations[:5],
        "reasoning_chain": state.get("reasoning_chain", []),
    }

    # LLM enhancement: executive summary
    try:
        from .prompts import SYSTEM_REPORT, ReportSummaryResult

        context = json.dumps(report, default=str)
        llm_result = cast(
            ReportSummaryResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Profiling report data:\n{context}",
                schema=ReportSummaryResult,
            ),
        )
        logger.info("llm_enhanced", agent="performance_profiler", node="generate_report")
        report["executive_summary"] = llm_result.executive_summary
        report["top_findings"] = llm_result.top_findings
        report["action_items"] = llm_result.action_items
    except Exception:
        logger.debug("llm_fallback", agent="performance_profiler", node="generate_report")
        report["executive_summary"] = (
            f"Profiled {report['total_spans_analyzed']} spans across "
            f"{report['endpoints_profiled']} endpoints. "
            f"Found {total_bottlenecks} bottlenecks "
            f"({critical_count} critical, {high_count} high) "
            f"and {report['contention_points']} contention points."
        )

    return {
        "stage": ProfilerStage.REPORT.value,
        "report": report,
        "reasoning_chain": state.get("reasoning_chain", [])
        + ["Compiled final performance profiling report"],
    }
