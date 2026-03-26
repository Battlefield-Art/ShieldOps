"""Node implementations for the Situation Manager Agent."""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.situation_manager.models import (
    ReasoningStep,
    SituationStage,
)
from shieldops.agents.situation_manager.prompts import (
    SYSTEM_NARRATIVE,
    SYSTEM_PRIORITIZE,
    SYSTEM_RECOMMEND,
    SYSTEM_REPORT,
    ActionOutput,
    NarrativeOutput,
    PrioritizationOutput,
    ReportOutput,
)
from shieldops.agents.situation_manager.tools import (
    SituationManagerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SituationManagerToolkit | None = None


def set_toolkit(
    toolkit: SituationManagerToolkit,
) -> None:
    """Set the global toolkit instance."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> SituationManagerToolkit:
    if _toolkit is None:
        return SituationManagerToolkit()
    return _toolkit


async def aggregate_alerts(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Aggregate related alerts into groups."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    aggregates = await toolkit.aggregate_related_alerts(
        tenant_id=state.get("tenant_id", ""),
        time_window_minutes=state.get("time_window_minutes", 60),
    )

    total = sum(a.alert_count for a in aggregates)

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="aggregate_alerts",
        input_summary=(f"tenant={state.get('tenant_id', '')}"),
        output_summary=(f"Aggregated {total} alerts into {len(aggregates)} groups"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="aggregate_related_alerts",
    )

    return {
        "aggregates": aggregates,
        "total_alerts_processed": total,
        "current_stage": (SituationStage.AGGREGATE_ALERTS),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def compose_narrative(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Compose narratives for alert aggregates."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    narratives = await toolkit.compose_narrative(
        state.get("aggregates", []),
    )

    # LLM enrichment for narratives
    for narr in narratives:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_NARRATIVE,
                user_prompt=(
                    f"Title: {narr.title}\n"
                    f"Summary: {narr.summary}\n"
                    f"Assets: "
                    f"{', '.join(narr.affected_assets)}"
                ),
                output_schema=NarrativeOutput,
            )
            narr.title = result.title
            narr.summary = result.summary
            narr.attack_story = result.attack_story
            narr.timeline = result.timeline
        except Exception:
            logger.warning(
                "situation_manager.llm_narrative_fallback",
                narrative_id=narr.id,
            )

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="compose_narrative",
        input_summary=(f"{len(state.get('aggregates', []))} aggregates"),
        output_summary=(f"Composed {len(narratives)} narratives"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="compose_narrative",
    )

    return {
        "narratives": narratives,
        "current_stage": (SituationStage.COMPOSE_NARRATIVE),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def prioritize_situations(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Prioritize situations based on risk."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    situations = await toolkit.prioritize_situations(
        narratives=state.get("narratives", []),
        aggregates=state.get("aggregates", []),
    )

    # LLM enrichment for prioritization
    for sit in situations:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_PRIORITIZE,
                user_prompt=(
                    f"Title: {sit.title}\n"
                    f"Severity: {sit.severity}\n"
                    f"Vendors: {sit.vendor_count}\n"
                    f"Alerts: {sit.alert_count}"
                ),
                output_schema=PrioritizationOutput,
            )
            sit.confidence = result.confidence
            sit.auto_actionable = result.auto_actionable
            sit.estimated_impact = result.estimated_impact
        except Exception:
            logger.warning(
                "situation_manager.llm_prioritize_fallback",
                situation_id=sit.id,
            )

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="prioritize_situations",
        input_summary=(f"{len(state.get('narratives', []))} narratives"),
        output_summary=(f"Prioritized {len(situations)} situations"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="prioritize_situations",
    )

    return {
        "situations": situations,
        "total_situations": len(situations),
        "current_stage": (SituationStage.PRIORITIZE_SITUATIONS),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def recommend_actions(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate action recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    recs = await toolkit.recommend_actions(
        state.get("situations", []),
    )

    # LLM enrichment
    for rec in recs:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_RECOMMEND,
                user_prompt=(
                    f"Action: {rec.action_type}\n"
                    f"Description: {rec.description}\n"
                    f"Urgency: {rec.urgency}"
                ),
                output_schema=ActionOutput,
            )
            rec.description = result.description
            rec.playbook_ref = result.playbook_ref
            rec.estimated_time_minutes = result.estimated_time_minutes
        except Exception:
            logger.warning(
                "situation_manager.llm_recommend_fallback",
                rec_id=rec.id,
            )

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="recommend_actions",
        input_summary=(f"{len(state.get('situations', []))} situations"),
        output_summary=(f"Generated {len(recs)} recommendations"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="recommend_actions",
    )

    return {
        "recommendations": recs,
        "current_stage": (SituationStage.RECOMMEND_ACTIONS),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def track_outcomes(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Initialize outcome tracking for situations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    outcomes = await toolkit.track_outcome(
        state.get("situations", []),
    )

    auto_count = sum(
        1 for s in state.get("situations", []) if s.auto_actionable if hasattr(s, "auto_actionable")
    )

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="track_outcomes",
        input_summary=(f"{len(state.get('situations', []))} situations"),
        output_summary=(f"Tracking {len(outcomes)} outcomes"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="track_outcome",
    )

    return {
        "outcomes": outcomes,
        "auto_resolved_count": auto_count,
        "current_stage": (SituationStage.TRACK_OUTCOMES),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def generate_report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate the final situation management report."""
    start = datetime.now(UTC)

    try:
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(
                f"Alerts: "
                f"{state.get('total_alerts_processed', 0)}"
                f"\nSituations: "
                f"{state.get('total_situations', 0)}"
                f"\nRecommendations: "
                f"{len(state.get('recommendations', []))}"
                f"\nAuto-resolved: "
                f"{state.get('auto_resolved_count', 0)}"
            ),
            output_schema=ReportOutput,
        )
        _ = result.executive_summary
    except Exception:
        logger.warning("situation_manager.llm_report_fallback")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="generate_report",
        input_summary=(f"{state.get('total_situations', 0)} situations"),
        output_summary="Report generated",
        duration_ms=elapsed,
        tool_used="llm_structured",
    )

    chain = state.get("reasoning_chain", [])
    total_ms = (
        sum(s.duration_ms if hasattr(s, "duration_ms") else s.get("duration_ms", 0) for s in chain)
        + elapsed
    )

    return {
        "current_stage": SituationStage.REPORT,
        "reasoning_chain": [*chain, step],
        "session_duration_ms": total_ms,
    }
