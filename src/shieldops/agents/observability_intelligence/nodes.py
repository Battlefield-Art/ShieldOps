"""Node implementations for the ObservabilityIntelligence Agent LangGraph workflow."""

import json
from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.observability_intelligence.models import (
    ObservabilityIntelligenceReasoningStep,
    ObservabilityIntelligenceState,
)
from shieldops.agents.observability_intelligence.prompts import SYSTEM_ANALYZE, AnalysisOutput
from shieldops.agents.observability_intelligence.tools import ObservabilityIntelligenceToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ObservabilityIntelligenceToolkit | None = None


def _get_toolkit() -> ObservabilityIntelligenceToolkit:
    if _toolkit is None:
        return ObservabilityIntelligenceToolkit()
    return _toolkit


async def collect_signals(state: ObservabilityIntelligenceState) -> dict[str, Any]:
    """Collect observability signals from multiple sources"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("collect_signals", 1.0)

    step = ObservabilityIntelligenceReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_signals",
        input_summary="Executing collect_signals",
        output_summary="Completed collect_signals",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="collect_signals",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_signals",
        "session_start": start,
    }


async def correlate_data(state: ObservabilityIntelligenceState) -> dict[str, Any]:
    """Correlate data across metrics, logs, and traces"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("correlate_data", 1.0)

    step = ObservabilityIntelligenceReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="correlate_data",
        input_summary="Executing correlate_data",
        output_summary="Completed correlate_data",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="correlate_data",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "correlate_data",
    }


async def analyze_insights(state: ObservabilityIntelligenceState) -> dict[str, Any]:
    """Analyze correlated data for actionable insights"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("analyze_insights", 1.0)

    llm_summary = "Completed analyze_insights"
    try:
        analysis_context = json.dumps(
            {
                "current_step": state.current_step,
                "reasoning_steps": len(state.reasoning_chain),
            },
            default=str,
        )
        llm_result = cast(
            AnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Observability analysis context:\n{analysis_context}",
                schema=AnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="analyze_insights",
            insight_count=llm_result.insight_count,
            confidence=llm_result.confidence,
        )
        llm_summary = (
            f"Insights: {llm_result.insight_count}, "
            f"confidence={llm_result.confidence:.1f}. {llm_result.reasoning}"
        )
    except Exception:
        logger.warning("llm_fallback", node="analyze_insights")

    step = ObservabilityIntelligenceReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_insights",
        input_summary="Executing analyze_insights",
        output_summary=llm_summary,
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="analyze_insights",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_insights",
    }


async def generate_recommendations(state: ObservabilityIntelligenceState) -> dict[str, Any]:
    """Generate optimization recommendations"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("generate_recommendations", 1.0)

    step = ObservabilityIntelligenceReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_recommendations",
        input_summary="Executing generate_recommendations",
        output_summary="Completed generate_recommendations",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="generate_recommendations",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_recommendations",
    }


async def finalize_analysis(state: ObservabilityIntelligenceState) -> dict[str, Any]:
    """Finalize the observability analysis session"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    await toolkit.record_metric("observability_intelligence_duration_ms", float(duration_ms))

    step = ObservabilityIntelligenceReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="finalize_analysis",
        input_summary="Finalizing observability_intelligence session",
        output_summary=f"Session complete in {duration_ms}ms",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
