"""Node implementations for the Threat Landscape
Analyzer Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.threat_landscape_analyzer.models import (
    ReasoningStep,
    ThreatLandscapeAnalyzerState,
    TLAStage,
)
from shieldops.agents.threat_landscape_analyzer.prompts import (
    SYSTEM_BENCHMARK,
    SYSTEM_BRIEF,
    SYSTEM_INDUSTRY,
    SYSTEM_TRENDS,
    BenchmarkOutput,
    IndustryMappingOutput,
    ThreatBriefOutput,
    TrendAnalysisOutput,
)
from shieldops.agents.threat_landscape_analyzer.tools import (
    ThreatLandscapeAnalyzerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ThreatLandscapeAnalyzerToolkit | None = None


def set_toolkit(
    toolkit: ThreatLandscapeAnalyzerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ThreatLandscapeAnalyzerToolkit:
    if _toolkit is None:
        return ThreatLandscapeAnalyzerToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: datetime,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: collect_intel
# ------------------------------------------------------------------


async def collect_intel(
    state: ThreatLandscapeAnalyzerState,
) -> dict[str, Any]:
    """Collect threat intelligence from configured
    sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.collect_intel(
        sources=state.intel_sources,
        time_range=state.time_range,
        scope=state.scope,
    )

    intel_items: list[dict[str, Any]] = list(results)

    step = _step(
        state.reasoning_chain,
        "collect_intel",
        (f"Sources: {len(state.intel_sources)}, range={state.time_range}"),
        f"Collected {len(intel_items)} intel items",
        start,
        "intel_aggregator",
    )

    return {
        "intel_items": intel_items,
        "total_threats": len(intel_items),
        "stage": TLAStage.COLLECT_INTEL,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_intel",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_trends
# ------------------------------------------------------------------


async def analyze_trends(
    state: ThreatLandscapeAnalyzerState,
) -> dict[str, Any]:
    """Analyze threat trends from collected intel."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    trends = await toolkit.analyze_trends(
        intel_items=state.intel_items,
        time_range=state.time_range,
    )

    trend_list: list[dict[str, Any]] = list(trends)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "item_count": len(state.intel_items),
                "intel_sample": state.intel_items[:5],
                "time_range": state.time_range,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_TRENDS,
            user_prompt=f"Analyze threat trends:\n{ctx}",
            schema=TrendAnalysisOutput,
        )
        if llm_out.trends:  # type: ignore[union-attr]
            _rand = random.randint(1000, 9999)  # noqa: S311
            trend_list.append(
                {
                    "trend_id": f"llm-{_rand}",
                    "trends": (
                        llm_out.trends  # type: ignore[union-attr]
                    ),
                    "emerging": (
                        llm_out.emerging_threats  # type: ignore[union-attr]
                    ),
                    "declining": (
                        llm_out.declining_threats  # type: ignore[union-attr]
                    ),
                    "confidence": (
                        llm_out.confidence  # type: ignore[union-attr]
                    ),
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_trends",
            count=len(llm_out.trends),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_trends",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_trends",
        f"Analyzing {len(state.intel_items)} intel items",
        f"Identified {len(trend_list)} trend groups",
        start,
        "trend_analyzer",
    )

    return {
        "trends": trend_list,
        "stage": TLAStage.ANALYZE_TRENDS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_trends",
    }


# ------------------------------------------------------------------
# Node: map_to_industry
# ------------------------------------------------------------------


async def map_to_industry(
    state: ThreatLandscapeAnalyzerState,
) -> dict[str, Any]:
    """Map threats to the target industry vertical."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    mapping = await toolkit.map_to_industry(
        trends=state.trends,
        industry=state.industry.value,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "industry": state.industry.value,
                "trend_count": len(state.trends),
                "trend_sample": state.trends[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_INDUSTRY,
            user_prompt=f"Map threats to industry:\n{ctx}",
            schema=IndustryMappingOutput,
        )
        if llm_out.relevant_threats:  # type: ignore[union-attr]
            mapping.update(
                {
                    "relevant_threats": (
                        llm_out.relevant_threats  # type: ignore[union-attr]
                    ),
                    "attack_vectors": (
                        llm_out.attack_vectors  # type: ignore[union-attr]
                    ),
                    "risk_multiplier": (
                        llm_out.risk_multiplier  # type: ignore[union-attr]
                    ),
                    "summary": (
                        llm_out.summary  # type: ignore[union-attr]
                    ),
                }
            )
        logger.info(
            "llm_enhanced",
            node="map_to_industry",
            threats=len(
                llm_out.relevant_threats  # type: ignore[union-attr]
            ),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="map_to_industry",
        )

    step = _step(
        state.reasoning_chain,
        "map_to_industry",
        (f"Mapping {len(state.trends)} trends to {state.industry.value}"),
        "Industry mapping complete",
        start,
        "industry_mapper",
    )

    return {
        "industry_mapping": mapping,
        "stage": TLAStage.MAP_TO_INDUSTRY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_to_industry",
    }


# ------------------------------------------------------------------
# Node: benchmark_posture
# ------------------------------------------------------------------


async def benchmark_posture(
    state: ThreatLandscapeAnalyzerState,
) -> dict[str, Any]:
    """Benchmark security posture against industry
    peers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    benchmark = await toolkit.benchmark_posture(
        industry_mapping=state.industry_mapping,
        posture_data=state.scope,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "industry": state.industry.value,
                "industry_mapping": state.industry_mapping,
                "posture_data": state.scope,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_BENCHMARK,
            user_prompt=f"Benchmark posture:\n{ctx}",
            schema=BenchmarkOutput,
        )
        if llm_out.validated:  # type: ignore[union-attr]
            benchmark.update(
                {
                    "peer_percentile": (
                        llm_out.peer_percentile  # type: ignore[union-attr]
                    ),
                    "gaps": (
                        llm_out.gaps  # type: ignore[union-attr]
                    ),
                    "strengths": (
                        llm_out.strengths  # type: ignore[union-attr]
                    ),
                    "recommendations": (
                        llm_out.recommendations  # type: ignore[union-attr]
                    ),
                }
            )
        logger.info(
            "llm_enhanced",
            node="benchmark_posture",
            validated=llm_out.validated,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="benchmark_posture",
        )

    percentile = benchmark.get("peer_percentile", 50)

    step = _step(
        state.reasoning_chain,
        "benchmark_posture",
        f"Benchmarking against {state.industry.value} peers",
        f"Percentile: {percentile}",
        start,
        "benchmark_engine",
    )

    return {
        "benchmark": benchmark,
        "peer_percentile": percentile,
        "stage": TLAStage.BENCHMARK_POSTURE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "benchmark_posture",
    }


# ------------------------------------------------------------------
# Node: generate_threat_brief
# ------------------------------------------------------------------


async def generate_threat_brief(
    state: ThreatLandscapeAnalyzerState,
) -> dict[str, Any]:
    """Generate an executive threat brief."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    brief = await toolkit.generate_threat_brief(
        trends=state.trends,
        industry_mapping=state.industry_mapping,
        benchmark=state.benchmark,
    )

    step = _step(
        state.reasoning_chain,
        "generate_threat_brief",
        (f"Briefing on {len(state.trends)} trends, percentile={state.peer_percentile}"),
        "Threat brief generated",
        start,
        "brief_generator",
    )

    return {
        "threat_brief": brief,
        "stage": TLAStage.GENERATE_BRIEF,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_threat_brief",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: ThreatLandscapeAnalyzerState,
) -> dict[str, Any]:
    """Generate the final landscape analysis report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # Compute posture score
    if state.peer_percentile > 75:
        posture = min(1.0, 0.7 + (state.peer_percentile * 0.003))
    elif state.peer_percentile > 50:
        posture = 0.5 + (state.peer_percentile * 0.003)
    else:
        posture = max(0.1, state.peer_percentile * 0.01)

    # Count critical threats
    critical_count = 0
    for item in state.intel_items:
        if item.get("severity") == "critical":
            critical_count += 1

    report: dict[str, Any] = {
        "industry": state.industry.value,
        "total_threats": state.total_threats,
        "critical_threats": critical_count,
        "peer_percentile": state.peer_percentile,
        "posture_score": posture,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "industry": state.industry.value,
                "total_threats": state.total_threats,
                "trends": state.trends[:5],
                "industry_mapping": state.industry_mapping,
                "benchmark": state.benchmark,
                "threat_brief": state.threat_brief,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_BRIEF,
            user_prompt=f"Generate landscape report:\n{ctx}",
            schema=ThreatBriefOutput,
        )
        if isinstance(llm_out, ThreatBriefOutput):
            report.update(
                {
                    "executive_summary": (llm_out.executive_summary),
                    "top_threats": llm_out.top_threats,
                    "recommendations": (llm_out.recommendations),
                    "risk_rating": llm_out.risk_rating,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recommendations=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Track metrics
    await toolkit.record_metric(
        request_id=state.request_id,
        outcome={
            "total_threats": state.total_threats,
            "critical_threats": critical_count,
            "peer_percentile": state.peer_percentile,
            "posture_score": posture,
        },
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_threats} threats"),
        f"Report generated, posture={posture:.2f}",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "posture_score": posture,
        "critical_threats": critical_count,
        "session_duration_ms": duration_ms,
        "stage": TLAStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
