"""Node implementations for the Post-Incident Analyzer LangGraph workflow."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.agents.post_incident_analyzer.models import (
    PostIncidentAnalyzerState,
    PostIncidentStage,
    RootCauseCategory,
)
from shieldops.agents.post_incident_analyzer.prompts import (
    SYSTEM_LESSONS,
    SYSTEM_RECOMMENDATIONS,
    SYSTEM_RECONSTRUCT_TIMELINE,
    SYSTEM_REPORT,
    SYSTEM_ROOT_CAUSE,
    LessonsOutput,
    RecommendationOutput,
    ReportOutput,
    RootCauseOutput,
    TimelineOutput,
)
from shieldops.agents.post_incident_analyzer.tools import (
    PostIncidentAnalyzerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: PostIncidentAnalyzerToolkit | None = None


def set_toolkit(toolkit: PostIncidentAnalyzerToolkit) -> None:
    """Set the shared toolkit instance for all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> PostIncidentAnalyzerToolkit:
    if _toolkit is None:
        return PostIncidentAnalyzerToolkit()
    return _toolkit


# ------------------------------------------------------------------
# Node: gather_timeline
# ------------------------------------------------------------------


async def gather_timeline(
    state: PostIncidentAnalyzerState,
) -> dict[str, Any]:
    """Collect and order timeline events for the incident."""
    start = time.time()
    toolkit = _get_toolkit()

    events = await toolkit.gather_timeline(state.incident_id)

    # LLM enhancement — identify gaps and refine ordering
    try:
        ctx = _json.dumps(
            {"incident_id": state.incident_id, "events": events},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RECONSTRUCT_TIMELINE,
            user_prompt=f"Reconstruct timeline:\n{ctx}",
            schema=TimelineOutput,
        )
        if hasattr(llm_result, "events") and llm_result.events:
            events = llm_result.events  # type: ignore[assignment]
        logger.info("llm_enhanced", node="gather_timeline")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="gather_timeline")

    elapsed = int((time.time() - start) * 1000)
    return {
        "timeline_events": events,
        "stage": PostIncidentStage.ROOT_CAUSE_ANALYSIS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Gathered {len(events)} timeline event(s) in {elapsed}ms",
        ],
        "session_start": (start if state.session_start == 0.0 else state.session_start),
    }


# ------------------------------------------------------------------
# Node: root_cause_analysis
# ------------------------------------------------------------------


async def root_cause_analysis(
    state: PostIncidentAnalyzerState,
) -> dict[str, Any]:
    """Determine root cause from timeline events."""
    start = time.time()
    toolkit = _get_toolkit()

    category, reasoning = await toolkit.analyze_root_cause(state.timeline_events)

    # LLM enhancement — five-whys and deeper analysis
    try:
        ctx = _json.dumps(
            {
                "timeline": state.timeline_events,
                "heuristic_category": category.value,
                "heuristic_reasoning": reasoning,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ROOT_CAUSE,
            user_prompt=f"Analyse root cause:\n{ctx}",
            schema=RootCauseOutput,
        )
        llm_cat = getattr(llm_result, "category", "")
        for rc in RootCauseCategory:
            if llm_cat == rc.value:
                category = rc
                break
        llm_primary = getattr(llm_result, "primary_cause", "")
        if llm_primary:
            reasoning = f"{reasoning} | LLM: {llm_primary}"
        logger.info("llm_enhanced", node="root_cause_analysis")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="root_cause_analysis")

    elapsed = int((time.time() - start) * 1000)
    return {
        "root_cause": category,
        "stage": PostIncidentStage.IMPACT_ASSESSMENT,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Root cause: {category.value} — {reasoning} ({elapsed}ms)",
        ],
    }


# ------------------------------------------------------------------
# Node: impact_assessment
# ------------------------------------------------------------------


async def impact_assessment(
    state: PostIncidentAnalyzerState,
) -> dict[str, Any]:
    """Assess the business impact of the incident."""
    start = time.time()
    toolkit = _get_toolkit()

    impact = await toolkit.assess_impact(state.incident_id, state.root_cause)

    elapsed = int((time.time() - start) * 1000)
    return {
        "impact": impact,
        "stage": PostIncidentStage.LESSONS_LEARNED,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Impact assessed as {impact.value} ({elapsed}ms)",
        ],
    }


# ------------------------------------------------------------------
# Node: lessons_learned
# ------------------------------------------------------------------


async def lessons_learned(
    state: PostIncidentAnalyzerState,
) -> dict[str, Any]:
    """Extract lessons learned from timeline and root cause."""
    start = time.time()
    toolkit = _get_toolkit()

    lessons = await toolkit.extract_lessons(state.timeline_events, state.root_cause)

    # LLM enhancement — deeper lesson extraction
    try:
        ctx = _json.dumps(
            {
                "timeline": state.timeline_events,
                "root_cause": state.root_cause.value,
                "impact": state.impact.value,
                "heuristic_lessons": lessons,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_LESSONS,
            user_prompt=f"Extract lessons:\n{ctx}",
            schema=LessonsOutput,
        )
        llm_lessons = getattr(llm_result, "lessons", [])
        if llm_lessons:
            for ll in llm_lessons:
                if isinstance(ll, dict) and ll not in lessons:
                    lessons.append(ll)
        logger.info("llm_enhanced", node="lessons_learned")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="lessons_learned")

    elapsed = int((time.time() - start) * 1000)
    # Store lessons temporarily in reasoning_chain for action_items
    return {
        "stage": PostIncidentStage.ACTION_ITEMS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Extracted {len(lessons)} lesson(s) ({elapsed}ms)",
            _json.dumps({"_lessons": lessons}, default=str),
        ],
    }


# ------------------------------------------------------------------
# Node: action_items
# ------------------------------------------------------------------


async def action_items(
    state: PostIncidentAnalyzerState,
) -> dict[str, Any]:
    """Generate action items from lessons learned."""
    start = time.time()
    toolkit = _get_toolkit()

    # Recover lessons from reasoning chain
    lessons: list[dict[str, str]] = []
    for entry in reversed(state.reasoning_chain):
        if isinstance(entry, str) and '"_lessons"' in entry:
            try:
                parsed = _json.loads(entry)
                lessons = parsed.get("_lessons", [])
            except Exception:
                logger.debug("lessons_parse_failed")
            break

    # Fallback: re-extract if not found
    if not lessons:
        lessons = await toolkit.extract_lessons(state.timeline_events, state.root_cause)

    items = await toolkit.generate_action_items(lessons)

    # LLM enhancement — refine recommendations
    try:
        ctx = _json.dumps(
            {
                "lessons": lessons,
                "root_cause": state.root_cause.value,
                "impact": state.impact.value,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RECOMMENDATIONS,
            user_prompt=f"Generate recommendations:\n{ctx}",
            schema=RecommendationOutput,
        )
        quick_wins = getattr(llm_result, "quick_wins", [])
        if quick_wins:
            state_reasoning = list(state.reasoning_chain)
            state_reasoning.append(f"LLM quick wins: {', '.join(quick_wins[:3])}")
        logger.info("llm_enhanced", node="action_items")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="action_items")

    elapsed = int((time.time() - start) * 1000)
    return {
        "action_items": items,
        "stage": PostIncidentStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Generated {len(items)} action item(s) ({elapsed}ms)",
        ],
    }


# ------------------------------------------------------------------
# Node: report
# ------------------------------------------------------------------


async def report(
    state: PostIncidentAnalyzerState,
) -> dict[str, Any]:
    """Generate the final post-incident report."""
    start = time.time()
    total_elapsed = int((time.time() - state.session_start) * 1000)

    summary = (
        f"Post-incident analysis for {state.incident_id}: "
        f"root_cause={state.root_cause.value}, "
        f"impact={state.impact.value}, "
        f"action_items={len(state.action_items)}, "
        f"timeline_events={len(state.timeline_events)}"
    )

    # LLM enhancement — executive report
    try:
        ctx = _json.dumps(
            {
                "incident_id": state.incident_id,
                "root_cause": state.root_cause.value,
                "impact": state.impact.value,
                "timeline_events": state.timeline_events[:20],
                "action_items": [a.model_dump() for a in state.action_items],
                "reasoning_chain": state.reasoning_chain[-10:],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate post-incident report:\n{ctx}",
            schema=ReportOutput,
        )
        exec_summary = getattr(llm_result, "executive_summary", "")
        if exec_summary:
            summary = exec_summary
        logger.info("llm_enhanced", node="report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="report")

    elapsed = int((time.time() - start) * 1000)
    return {
        "stage": PostIncidentStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report generated in {elapsed}ms (total {total_elapsed}ms): {summary}",
        ],
    }
