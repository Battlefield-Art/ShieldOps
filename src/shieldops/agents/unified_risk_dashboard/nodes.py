"""Node implementations for the Unified Risk Dashboard LangGraph workflow.

Each node is an async function that:
1. Queries risk systems via the toolkit
2. Uses the LLM to analyze and reason about data
3. Updates the URD state with findings
4. Records its reasoning step in the audit trail
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.unified_risk_dashboard.models import (
    AggregatedRisk,
    NormalizedScore,
    ReasoningStep,
    RiskSignal,
    UnifiedRiskDashboardState,
    URDStage,
)
from shieldops.agents.unified_risk_dashboard.prompts import (
    SYSTEM_AGGREGATE_RISKS,
    SYSTEM_CALCULATE_POSTURE,
    SYSTEM_COLLECT_SIGNALS,
    SYSTEM_NORMALIZE_SCORES,
    SYSTEM_PRIORITIZE_ACTIONS,
    AggregationAnalysis,
    NormalizationAnalysis,
    PostureAnalysis,
    PrioritizationAnalysis,
    SignalCollectionAnalysis,
)
from shieldops.agents.unified_risk_dashboard.tools import (
    UnifiedRiskDashboardToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit, set by runner at startup.
_toolkit: UnifiedRiskDashboardToolkit | None = None


def set_toolkit(
    toolkit: UnifiedRiskDashboardToolkit,
) -> None:
    """Configure toolkit used by all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> UnifiedRiskDashboardToolkit:
    if _toolkit is None:
        return UnifiedRiskDashboardToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# ---- Node: collect_risk_signals ----


async def collect_risk_signals(
    state: UnifiedRiskDashboardState,
) -> dict[str, Any]:
    """Collect risk signals from security agents."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "urd_collecting_signals",
        request_id=state.request_id,
    )

    domains = state.config.get("domains")
    signals = await toolkit.collect_risk_signals(
        tenant_id=state.tenant_id,
        domains=domains,
    )

    domains_seen = list({s.domain.value for s in signals})
    output_summary = f"Collected {len(signals)} risk signals across {len(domains_seen)} domains."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "signals_collected": len(signals),
                "domains": domains_seen,
                "sources": list({s.source_agent for s in signals}),
                "severities": [s.severity for s in signals],
            },
            default=str,
        )
        llm_result = cast(
            SignalCollectionAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_COLLECT_SIGNALS,
                user_prompt=(f"Signal collection results:\n{ctx}"),
                schema=SignalCollectionAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(signals)} signals."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_risk_signals",
        )

    step = ReasoningStep(
        step_number=1,
        action="collect_risk_signals",
        input_summary=("Collecting risk signals from agent fleet"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="signal_collector",
    )

    return {
        "risk_signals": [s.model_dump() for s in signals],
        "signal_count": len(signals),
        "domain_count": len(domains_seen),
        "stage": URDStage.NORMALIZE_SCORES,
        "session_start": start,
        "reasoning_chain": [step],
        "current_step": "collect_risk_signals",
    }


# ---- Node: normalize_scores ----


async def normalize_scores(
    state: UnifiedRiskDashboardState,
) -> dict[str, Any]:
    """Normalize risk scores for cross-domain comparison."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    signals = [RiskSignal.model_validate(s) for s in state.risk_signals]

    logger.info(
        "urd_normalizing_scores",
        request_id=state.request_id,
        signal_count=len(signals),
    )

    normalized = await toolkit.normalize_scores(signals)

    output_summary = f"Normalized {len(normalized)} risk scores."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "signals": len(signals),
                "normalized": len(normalized),
                "avg_score": round(
                    sum(n.normalized_score for n in normalized) / max(len(normalized), 1),
                    3,
                ),
            },
            default=str,
        )
        llm_result = cast(
            NormalizationAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_NORMALIZE_SCORES,
                user_prompt=(f"Normalization results:\n{ctx}"),
                schema=NormalizationAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Distribution: {llm_result.distribution}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="normalize_scores",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="normalize_scores",
        input_summary=(f"Normalizing {len(signals)} risk scores"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="score_normalizer",
    )

    return {
        "normalized_scores": [n.model_dump() for n in normalized],
        "stage": URDStage.AGGREGATE_RISKS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "normalize_scores",
    }


# ---- Node: aggregate_risks ----


async def aggregate_risks(
    state: UnifiedRiskDashboardState,
) -> dict[str, Any]:
    """Aggregate normalized scores by domain."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    normalized = [NormalizedScore.model_validate(n) for n in state.normalized_scores]

    logger.info(
        "urd_aggregating_risks",
        request_id=state.request_id,
        score_count=len(normalized),
    )

    aggregated = await toolkit.aggregate_risks(normalized)
    critical_domains = sum(1 for a in aggregated if a.aggregate_score > 0.7)

    output_summary = f"Aggregated {len(aggregated)} domains. {critical_domains} at high risk."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "scores": len(normalized),
                "domains": len(aggregated),
                "critical_domains": critical_domains,
                "domain_scores": {a.domain.value: a.aggregate_score for a in aggregated},
            },
            default=str,
        )
        llm_result = cast(
            AggregationAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_AGGREGATE_RISKS,
                user_prompt=(f"Risk aggregation results:\n{ctx}"),
                schema=AggregationAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Risk: {llm_result.risk_assessment}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="aggregate_risks",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="aggregate_risks",
        input_summary=(f"Aggregating {len(normalized)} scores by domain"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="risk_aggregator",
    )

    return {
        "aggregated_risks": [a.model_dump() for a in aggregated],
        "stage": URDStage.CALCULATE_POSTURE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "aggregate_risks",
    }


# ---- Node: calculate_posture ----


async def calculate_posture(
    state: UnifiedRiskDashboardState,
) -> dict[str, Any]:
    """Calculate overall security posture."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    aggregated = [AggregatedRisk.model_validate(a) for a in state.aggregated_risks]

    logger.info(
        "urd_calculating_posture",
        request_id=state.request_id,
        domain_count=len(aggregated),
    )

    posture = await toolkit.calculate_posture(aggregated)

    output_summary = (
        f"Posture: {posture.posture_level.value} "
        f"(score: {posture.overall_score:.2f}). "
        f"Trend: {posture.trend}."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "domains": len(aggregated),
                "overall_score": posture.overall_score,
                "level": posture.posture_level.value,
                "strengths": posture.strengths,
                "weaknesses": posture.weaknesses,
                "trend": posture.trend,
            },
            default=str,
        )
        llm_result = cast(
            PostureAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_CALCULATE_POSTURE,
                user_prompt=(f"Posture calculation results:\n{ctx}"),
                schema=PostureAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Level: {llm_result.overall_level}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="calculate_posture",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="calculate_posture",
        input_summary=(f"Calculating posture from {len(aggregated)} domains"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="posture_calculator",
    )

    return {
        "posture": [posture.model_dump()],
        "stage": URDStage.PRIORITIZE_ACTIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "calculate_posture",
    }


# ---- Node: prioritize_actions ----


async def prioritize_actions(
    state: UnifiedRiskDashboardState,
) -> dict[str, Any]:
    """Prioritize remediation actions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    aggregated = [AggregatedRisk.model_validate(a) for a in state.aggregated_risks]

    from shieldops.agents.unified_risk_dashboard.models import (
        PostureAssessment,
    )

    posture_data = state.posture[0] if state.posture else {}
    posture = PostureAssessment.model_validate(posture_data)

    logger.info(
        "urd_prioritizing_actions",
        request_id=state.request_id,
        domain_count=len(aggregated),
    )

    actions = await toolkit.prioritize_actions(aggregated, posture)

    output_summary = f"Prioritized {len(actions)} remediation actions."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "domains": len(aggregated),
                "actions": len(actions),
                "top_actions": [a.title for a in actions[:3]],
                "posture_level": posture.posture_level.value,
            },
            default=str,
        )
        llm_result = cast(
            PrioritizationAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_PRIORITIZE_ACTIONS,
                user_prompt=(f"Action prioritization results:\n{ctx}"),
                schema=PrioritizationAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Impact: {llm_result.expected_impact}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="prioritize_actions",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="prioritize_actions",
        input_summary=(f"Prioritizing actions for {len(aggregated)} domains"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="action_prioritizer",
    )

    return {
        "prioritized_actions": [a.model_dump() for a in actions],
        "action_count": len(actions),
        "stage": URDStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "prioritize_actions",
    }


# ---- Node: generate_report ----


async def generate_report(
    state: UnifiedRiskDashboardState,
) -> dict[str, Any]:
    """Final reporting node -- summarize the risk dashboard."""
    start = datetime.now(UTC)

    session_duration_ms = 0
    if state.session_start:
        session_duration_ms = _elapsed_ms(state.session_start)

    posture_level = "unknown"
    overall_score = 0.0
    if state.posture:
        posture_level = state.posture[0].get("posture_level", "unknown")
        overall_score = state.posture[0].get("overall_score", 0.0)

    output_summary = (
        f"URD cycle complete. "
        f"{state.signal_count} signals, "
        f"{state.domain_count} domains, "
        f"posture: {posture_level} "
        f"({overall_score:.2f}), "
        f"{state.action_count} actions. "
        f"Duration: {session_duration_ms}ms."
    )

    logger.info(
        "urd_report",
        request_id=state.request_id,
        summary=output_summary,
    )

    report = {
        "request_id": state.request_id,
        "tenant_id": state.tenant_id,
        "signals_collected": state.signal_count,
        "domains_analyzed": state.domain_count,
        "scores_normalized": len(state.normalized_scores),
        "risks_aggregated": len(state.aggregated_risks),
        "posture_level": posture_level,
        "overall_score": overall_score,
        "actions_prioritized": state.action_count,
        "duration_ms": session_duration_ms,
        "summary": output_summary,
    }

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=("Generating final risk dashboard report"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": session_duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
