"""Node implementations for the TIP LangGraph workflow.

Each node is an async function that:
1. Queries external systems via the toolkit
2. Uses the LLM to analyze and reason about data
3. Updates the TIP state with findings
4. Records its reasoning step in the audit trail
"""

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.threat_intelligence_platform.models import (
    IntelSource,
    IntelStage,
    ReasoningStep,
    ThreatCorrelation,
    ThreatIntelligencePlatformState,
)
from shieldops.agents.threat_intelligence_platform.prompts import (
    SYSTEM_ADVISE,
    SYSTEM_ASSESS,
    SYSTEM_COLLECT,
    SYSTEM_CORRELATE,
    SYSTEM_NORMALIZE,
    AdvisoryAnalysis,
    CollectionAnalysis,
    CorrelationAnalysis,
    NormalizationAnalysis,
    RelevanceAnalysis,
)
from shieldops.agents.threat_intelligence_platform.tools import (
    ThreatIntelligencePlatformToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit, set by runner at startup.
_toolkit: ThreatIntelligencePlatformToolkit | None = None


def set_toolkit(
    toolkit: ThreatIntelligencePlatformToolkit,
) -> None:
    """Configure toolkit used by all nodes."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> ThreatIntelligencePlatformToolkit:
    if _toolkit is None:
        return ThreatIntelligencePlatformToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# ---- Node: collect_intelligence ----


async def collect_intelligence(
    state: ThreatIntelligencePlatformState,
) -> dict[str, Any]:
    """Collect raw intelligence from all sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sources = state.sources or [
        IntelSource.OSINT,
        IntelSource.INTERNAL_TELEMETRY,
    ]

    logger.info(
        "tip_collecting",
        request_id=state.request_id,
        sources=[s.value for s in sources],
    )

    items = await toolkit.collect_intelligence(sources, tenant_id=state.tenant_id)

    output_summary = f"Collected {len(items)} items from {len(sources)} sources."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "items_collected": len(items),
                "sources": [s.value for s in sources],
                "sample_types": list({i.raw_type for i in items[:20]}),
            },
            default=str,
        )
        llm_result = cast(
            CollectionAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_COLLECT,
                user_prompt=(f"Collection results:\n{ctx}"),
                schema=CollectionAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(items)} items collected."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_intelligence",
        )

    step = ReasoningStep(
        step_number=1,
        action="collect_intelligence",
        input_summary=(f"Sources: {[s.value for s in sources]}"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="multi_source_collector",
    )

    return {
        "items_collected": items,
        "sources": sources,
        "stage": IntelStage.NORMALIZE,
        "session_start": start,
        "reasoning_chain": [step],
        "current_step": "collect_intelligence",
    }


# ---- Node: normalize_indicators ----


async def normalize_indicators(
    state: ThreatIntelligencePlatformState,
) -> dict[str, Any]:
    """Normalize raw items to STIX/TAXII format."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "tip_normalizing",
        request_id=state.request_id,
        item_count=len(state.items_collected),
    )

    indicators = await toolkit.normalize_to_stix(state.items_collected)

    dedup_count = len(state.items_collected) - len(indicators)
    output_summary = (
        f"Normalized {len(indicators)} indicators "
        f"from {len(state.items_collected)} items. "
        f"{dedup_count} duplicates removed."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "raw_count": len(state.items_collected),
                "normalized_count": len(indicators),
                "stix_types": list({i.stix_type for i in indicators}),
                "dedup_removed": dedup_count,
            },
            default=str,
        )
        llm_result = cast(
            NormalizationAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_NORMALIZE,
                user_prompt=(f"Normalization results:\n{ctx}"),
                schema=NormalizationAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(indicators)} normalized."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="normalize_indicators",
        )

    step = ReasoningStep(
        step_number=(len(state.reasoning_chain) + 1),
        action="normalize_indicators",
        input_summary=(f"Normalizing {len(state.items_collected)} raw items to STIX"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="stix_normalizer",
    )

    return {
        "indicators_normalized": indicators,
        "stage": IntelStage.CORRELATE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "normalize_indicators",
    }


# ---- Node: correlate_threats ----


async def correlate_threats(
    state: ThreatIntelligencePlatformState,
) -> dict[str, Any]:
    """Correlate indicators across sources + internal."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "tip_correlating",
        request_id=state.request_id,
        indicator_count=len(state.indicators_normalized),
    )

    correlations: list[ThreatCorrelation] = []
    if state.indicators_normalized:
        correlations = await toolkit.correlate_cross_source(state.indicators_normalized)

    matched = sum(1 for c in correlations if c.match_count > 0)
    total_matches = sum(c.match_count for c in correlations)
    output_summary = (
        f"Correlated {len(state.indicators_normalized)}"
        f" indicators. {matched} had internal matches"
        f" ({total_matches} total hits)."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "indicators": len(state.indicators_normalized),
                "correlations": len(correlations),
                "internal_matches": total_matches,
                "multi_source": sum(1 for c in correlations if len(c.sources_matched) > 1),
            },
            default=str,
        )
        llm_result = cast(
            CorrelationAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_CORRELATE,
                user_prompt=(f"Correlation results:\n{ctx}"),
                schema=CorrelationAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {matched} internal matches."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="correlate_threats",
        )

    step = ReasoningStep(
        step_number=(len(state.reasoning_chain) + 1),
        action="correlate_threats",
        input_summary=(f"Correlating {len(state.indicators_normalized)} indicators across sources"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="cross_source_correlator",
    )

    return {
        "correlations": correlations,
        "stage": IntelStage.ASSESS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "correlate_threats",
    }


# ---- Node: assess_relevance ----


async def assess_relevance(
    state: ThreatIntelligencePlatformState,
) -> dict[str, Any]:
    """Assess relevance of each indicator to env."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "tip_assessing",
        request_id=state.request_id,
        correlation_count=len(state.correlations),
    )

    # Build correlation lookup by indicator ID
    corr_by_id: dict[str, ThreatCorrelation] = {}
    for c in state.correlations:
        for ind_id in c.indicator_ids:
            corr_by_id[ind_id] = c

    assessments = []
    for indicator in state.indicators_normalized:
        corr = corr_by_id.get(
            indicator.indicator_id,
            ThreatCorrelation(indicator_ids=[indicator.indicator_id]),
        )
        assessment = await toolkit.assess_relevance(indicator, corr)
        assessments.append(assessment)

    actionable_count = sum(1 for a in assessments if a.actionable)
    high_priority = sum(1 for a in assessments if a.relevance_score >= 0.7)

    output_summary = (
        f"Assessed {len(assessments)} indicators. "
        f"{actionable_count} actionable, "
        f"{high_priority} high-priority."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "total": len(assessments),
                "actionable": actionable_count,
                "high_priority": high_priority,
                "assessments": [
                    {
                        "id": a.indicator_id,
                        "relevance": a.relevance.value,
                        "score": a.relevance_score,
                        "actionable": a.actionable,
                        "drp_flags": (a.digital_risk_flags),
                    }
                    for a in assessments[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RelevanceAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_ASSESS,
                user_prompt=(f"Relevance assessment:\n{ctx}"),
                schema=RelevanceAnalysis,
            ),
        )
        output_summary = (
            f"{llm_result.summary} {actionable_count} actionable. Risk: {llm_result.overall_risk}."
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_relevance",
        )

    step = ReasoningStep(
        step_number=(len(state.reasoning_chain) + 1),
        action="assess_relevance",
        input_summary=(
            f"Assessing "
            f"{len(state.indicators_normalized)} "
            f"indicators with "
            f"{len(state.correlations)} correlations"
        ),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="relevance_scorer",
    )

    return {
        "assessments": assessments,
        "actionable_intel_count": actionable_count,
        "high_priority_count": high_priority,
        "confidence_score": max(
            (a.relevance_score for a in assessments),
            default=0.0,
        ),
        "stage": IntelStage.ADVISE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "assess_relevance",
    }


# ---- Node: generate_advisories ----


async def generate_advisories(
    state: ThreatIntelligencePlatformState,
) -> dict[str, Any]:
    """Generate threat advisories from assessments."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "tip_generating_advisories",
        request_id=state.request_id,
        assessment_count=len(state.assessments),
    )

    advisories = await toolkit.generate_advisories(
        state.assessments,
        state.correlations,
        state.indicators_normalized,
    )

    output_summary = (
        f"Generated {len(advisories)} advisories "
        f"from {state.actionable_intel_count} "
        f"actionable indicators."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "advisories": len(advisories),
                "actionable": (state.actionable_intel_count),
                "severities": [a.severity.value for a in advisories],
            },
            default=str,
        )
        llm_result = cast(
            AdvisoryAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_ADVISE,
                user_prompt=(f"Advisory generation:\n{ctx}"),
                schema=AdvisoryAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(advisories)} advisories."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_advisories",
        )

    step = ReasoningStep(
        step_number=(len(state.reasoning_chain) + 1),
        action="generate_advisories",
        input_summary=(f"Generating advisories from {len(state.assessments)} assessments"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="advisory_generator",
    )

    return {
        "advisories_generated": advisories,
        "stage": IntelStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "generate_advisories",
    }


# ---- Node: report ----


async def report(
    state: ThreatIntelligencePlatformState,
) -> dict[str, Any]:
    """Final reporting node — summarize the cycle."""
    start = datetime.now(UTC)

    session_duration_ms = 0
    if state.session_start:
        session_duration_ms = _elapsed_ms(state.session_start)

    output_summary = (
        f"TIP cycle complete. "
        f"{len(state.items_collected)} collected, "
        f"{len(state.indicators_normalized)} "
        f"normalized, "
        f"{len(state.correlations)} correlated, "
        f"{state.actionable_intel_count} actionable, "
        f"{len(state.advisories_generated)} "
        f"advisories. "
        f"Duration: {session_duration_ms}ms."
    )

    logger.info(
        "tip_report",
        request_id=state.request_id,
        summary=output_summary,
    )

    step = ReasoningStep(
        step_number=(len(state.reasoning_chain) + 1),
        action="report",
        input_summary="Generating final report",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="report_generator",
    )

    return {
        "session_duration_ms": session_duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
