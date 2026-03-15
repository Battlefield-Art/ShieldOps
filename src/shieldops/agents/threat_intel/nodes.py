"""Node implementations for the Threat Intel Agent LangGraph workflow.

Each node is an async function that:
1. Queries external systems via the ThreatIntelToolkit
2. Uses the LLM to analyze and reason about the data
3. Updates the threat intel state with findings
4. Records its reasoning step in the audit trail
"""

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.threat_intel.models import (
    IntelCorrelation,
    IntelSource,
    IntelStage,
    ReasoningStep,
    ThreatAssessment,
    ThreatIntelState,
)
from shieldops.agents.threat_intel.prompts import SYSTEM_ASSESS, AssessmentResult
from shieldops.agents.threat_intel.tools import ThreatIntelToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit reference, set by the runner at graph construction time.
_toolkit: ThreatIntelToolkit | None = None


def set_toolkit(toolkit: ThreatIntelToolkit) -> None:
    """Configure the toolkit used by all nodes. Called once at startup."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> ThreatIntelToolkit:
    if _toolkit is None:
        return ThreatIntelToolkit()  # Empty toolkit — safe for tests
    return _toolkit


async def collect_indicators(state: ThreatIntelState) -> dict[str, Any]:
    """Collect threat indicators from configured intelligence feeds.

    Queries all requested sources and aggregates the resulting indicators.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sources = state.sources or [
        IntelSource.OSINT,
        IntelSource.INTERNAL,
    ]

    logger.info(
        "threat_intel_collecting",
        request_id=state.request_id,
        sources=[s.value for s in sources],
    )

    indicators = await toolkit.collect_from_feeds(sources)

    # Count high-confidence indicators
    high_conf_count = sum(1 for ind in indicators if ind.confidence in ("confirmed", "probable"))

    output_summary = (
        f"Collected {len(indicators)} indicators from "
        f"{len(sources)} sources. "
        f"{high_conf_count} high-confidence."
    )

    step = ReasoningStep(
        step_number=1,
        action="collect_indicators",
        input_summary=f"Sources: {[s.value for s in sources]}",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="intel_feeds",
    )

    return {
        "indicators_collected": indicators,
        "sources": sources,
        "stage": IntelStage.CORRELATE,
        "session_start": start,
        "reasoning_chain": [step],
        "current_step": "collect_indicators",
    }


async def correlate_observations(state: ThreatIntelState) -> dict[str, Any]:
    """Correlate collected indicators against internal logs and events."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "threat_intel_correlating",
        request_id=state.request_id,
        indicator_count=len(state.indicators_collected),
    )

    correlations: list[IntelCorrelation] = []
    if state.indicators_collected:
        correlations = await toolkit.correlate_with_internal(state.indicators_collected)

    matched_count = sum(1 for c in correlations if c.match_count > 0)
    total_matches = sum(c.match_count for c in correlations)
    affected = set()
    for c in correlations:
        affected.update(c.entities_affected)

    output_summary = (
        f"Correlated {len(state.indicators_collected)} indicators. "
        f"{matched_count} had internal matches ({total_matches} total hits). "
        f"{len(affected)} entities affected."
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="correlate_observations",
        input_summary=(
            f"Correlating {len(state.indicators_collected)} indicators against internal data"
        ),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="siem_correlator",
    )

    return {
        "correlations": correlations,
        "stage": IntelStage.ASSESS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "correlate_observations",
    }


async def assess_threats(state: ThreatIntelState) -> dict[str, Any]:
    """Assess relevance and actionability of each correlated indicator."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "threat_intel_assessing",
        request_id=state.request_id,
        correlation_count=len(state.correlations),
    )

    assessments: list[ThreatAssessment] = []

    # Build a lookup of correlations by indicator value
    corr_by_value: dict[str, IntelCorrelation] = {c.indicator_value: c for c in state.correlations}

    for indicator in state.indicators_collected:
        correlation = corr_by_value.get(
            indicator.value,
            IntelCorrelation(indicator_value=indicator.value),
        )
        assessment = await toolkit.assess_relevance(indicator, correlation)
        assessments.append(assessment)

    actionable_count = sum(1 for a in assessments if a.actionable)
    high_priority = sum(1 for a in assessments if a.relevance_score >= 0.8)

    output_summary = (
        f"Assessed {len(assessments)} indicators. "
        f"{actionable_count} actionable, {high_priority} high-priority."
    )

    # LLM enhancement: deeper threat assessment reasoning
    try:
        import json

        assessment_context = json.dumps(
            {
                "total_indicators": len(state.indicators_collected),
                "correlations": len(state.correlations),
                "assessments": [
                    {
                        "indicator": a.indicator_value,
                        "relevance": a.relevance_score,
                        "actionable": a.actionable,
                    }
                    for a in assessments[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            AssessmentResult,
            await llm_structured(
                system_prompt=SYSTEM_ASSESS,
                user_prompt=f"Threat assessment context:\n{assessment_context}",
                schema=AssessmentResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="assess_threats",
            overall_risk=llm_result.overall_risk,
            actionable_count=llm_result.actionable_count,
        )
        output_summary = (
            f"{llm_result.summary} "
            f"{actionable_count} actionable, {high_priority} high-priority. "
            f"Overall risk: {llm_result.overall_risk}."
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="assess_threats")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_threats",
        input_summary=(
            f"Assessing {len(state.indicators_collected)} indicators "
            f"with {len(state.correlations)} correlations"
        ),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="relevance_scorer",
    )

    return {
        "assessments": assessments,
        "high_priority_count": high_priority,
        "confidence_score": (max((a.relevance_score for a in assessments), default=0.0)),
        "stage": IntelStage.DISTRIBUTE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_threats",
    }


async def distribute_intel(state: ThreatIntelState) -> dict[str, Any]:
    """Generate IOC report and distribute to defensive systems."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "threat_intel_distributing",
        request_id=state.request_id,
        assessment_count=len(state.assessments),
    )

    # Generate the IOC report
    report = await toolkit.generate_ioc_report(state.assessments)

    # Determine distribution channels
    channels = state.distribution_channels or [
        "siem",
        "firewall",
        "edr",
    ]

    # Distribute to channels
    dist_results = await toolkit.distribute_intel(report, channels)

    successful = sum(1 for r in dist_results.values() if r.get("status") == "success")

    output_summary = (
        f"Generated IOC report with {report.get('actionable_count', 0)} "
        f"actionable indicators. Distributed to {successful}/{len(channels)} "
        f"channels."
    )

    # Calculate session duration
    session_duration_ms = 0
    if state.session_start:
        session_duration_ms = _elapsed_ms(state.session_start)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="distribute_intel",
        input_summary=(f"Distributing {len(state.assessments)} assessed indicators to {channels}"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="distribution_engine",
    )

    return {
        "distribution_channels": channels,
        "distribution_results": dist_results,
        "session_duration_ms": session_duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }


# --- Private helpers ---


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)
