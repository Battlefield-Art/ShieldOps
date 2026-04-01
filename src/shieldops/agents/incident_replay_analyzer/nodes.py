"""Node implementations for the Incident Replay Analyzer."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.incident_replay_analyzer.models import (
    IncidentReplayAnalyzerState,
    IRAStage,
    ReasoningStep,
)
from shieldops.agents.incident_replay_analyzer.prompts import (
    SYSTEM_DECISIONS,
    SYSTEM_IMPROVEMENTS,
    SYSTEM_PLAYBOOKS,
    SYSTEM_SELECT,
    SYSTEM_TIMELINE,
    DecisionAnalysisOutput,
    ImprovementOutput,
    IncidentSelectionOutput,
    PlaybookOutput,
    TimelineOutput,
)
from shieldops.agents.incident_replay_analyzer.tools import (
    IncidentReplayAnalyzerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IncidentReplayAnalyzerToolkit | None = None


def set_toolkit(
    toolkit: IncidentReplayAnalyzerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> IncidentReplayAnalyzerToolkit:
    if _toolkit is None:
        return IncidentReplayAnalyzerToolkit()
    return _toolkit


def _step(
    state: IncidentReplayAnalyzerState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def select_incidents(
    state: IncidentReplayAnalyzerState,
) -> dict[str, Any]:
    """Select incidents for replay."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    selected = await toolkit.select_incidents(state.config)

    try:
        ctx = _json.dumps(
            {"count": len(selected)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SELECT,
            user_prompt=f"Incident selection context:\n{ctx}",
            schema=IncidentSelectionOutput,
        )
        if hasattr(llm_result, "incidents_selected"):
            logger.info(
                "llm_enhanced",
                node="select_incidents",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="select_incidents",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "select_incidents",
        f"config={state.config}",
        f"selected {len(selected)} incidents",
        elapsed,
        "incident_store",
    )
    await toolkit.record_metric(
        "incidents_selected",
        float(len(selected)),
    )

    return {
        "selected_incidents": selected,
        "stage": IRAStage.RECONSTRUCT_TIMELINE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "select_incidents",
        "session_start": start,
    }


async def reconstruct_timeline(
    state: IncidentReplayAnalyzerState,
) -> dict[str, Any]:
    """Reconstruct incident timelines."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    events = await toolkit.reconstruct_timeline(
        state.selected_incidents,
    )

    try:
        ctx = _json.dumps(
            {
                "incidents": len(state.selected_incidents),
                "events": len(events),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_TIMELINE,
            user_prompt=f"Timeline context:\n{ctx}",
            schema=TimelineOutput,
        )
        if hasattr(llm_result, "events_reconstructed"):
            logger.info(
                "llm_enhanced",
                node="reconstruct_timeline",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="reconstruct_timeline",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "reconstruct_timeline",
        f"replaying {len(state.selected_incidents)} incidents",
        f"{len(events)} timeline events",
        elapsed,
        "incident_store",
    )

    return {
        "timeline_events": events,
        "stage": IRAStage.ANALYZE_DECISIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "reconstruct_timeline",
    }


async def analyze_decisions(
    state: IncidentReplayAnalyzerState,
) -> dict[str, Any]:
    """Analyze decisions from timelines."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_decisions(
        state.timeline_events,
    )

    try:
        ctx = _json.dumps(
            {
                "events": len(state.timeline_events),
                "decisions": len(analyses),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DECISIONS,
            user_prompt=f"Decision analysis context:\n{ctx}",
            schema=DecisionAnalysisOutput,
        )
        if hasattr(llm_result, "decisions_analyzed"):
            logger.info(
                "llm_enhanced",
                node="analyze_decisions",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_decisions",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "analyze_decisions",
        f"analyzing {len(state.timeline_events)} events",
        f"{len(analyses)} decisions analyzed",
        elapsed,
        "analyzer",
    )

    return {
        "decision_analyses": analyses,
        "stage": IRAStage.IDENTIFY_IMPROVEMENTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_decisions",
    }


async def identify_improvements(
    state: IncidentReplayAnalyzerState,
) -> dict[str, Any]:
    """Identify improvements from analyses."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    improvements = await toolkit.identify_improvements(
        state.decision_analyses,
    )

    try:
        ctx = _json.dumps(
            {
                "analyses": len(state.decision_analyses),
                "improvements": len(improvements),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_IMPROVEMENTS,
            user_prompt=f"Improvement context:\n{ctx}",
            schema=ImprovementOutput,
        )
        if hasattr(llm_result, "improvements_found"):
            logger.info(
                "llm_enhanced",
                node="identify_improvements",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="identify_improvements",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "identify_improvements",
        f"reviewing {len(state.decision_analyses)} analyses",
        f"{len(improvements)} improvements found",
        elapsed,
        "analyzer",
    )
    await toolkit.record_metric(
        "improvements_found",
        float(len(improvements)),
    )

    return {
        "improvements": improvements,
        "stage": IRAStage.GENERATE_PLAYBOOKS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_improvements",
    }


async def generate_playbooks(
    state: IncidentReplayAnalyzerState,
) -> dict[str, Any]:
    """Generate playbooks from improvements."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    playbooks = await toolkit.generate_playbooks(
        state.improvements,
        state.selected_incidents,
    )

    try:
        ctx = _json.dumps(
            {
                "improvements": len(state.improvements),
                "playbooks": len(playbooks),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PLAYBOOKS,
            user_prompt=f"Playbook generation context:\n{ctx}",
            schema=PlaybookOutput,
        )
        if hasattr(llm_result, "playbooks_generated"):
            logger.info(
                "llm_enhanced",
                node="generate_playbooks",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_playbooks",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "generate_playbooks",
        f"generating from {len(state.improvements)} improvements",
        f"{len(playbooks)} playbooks generated",
        elapsed,
        "playbook_engine",
    )

    return {
        "playbooks": playbooks,
        "stage": IRAStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_playbooks",
    }


async def generate_report(
    state: IncidentReplayAnalyzerState,
) -> dict[str, Any]:
    """Generate final replay analysis report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "incidents_replayed": len(state.selected_incidents),
        "timeline_events": len(state.timeline_events),
        "decisions_analyzed": len(state.decision_analyses),
        "improvements": len(state.improvements),
        "playbooks": len(state.playbooks),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "generate_report",
        f"finalizing {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
