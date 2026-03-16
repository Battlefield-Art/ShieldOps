"""Node implementations for the SecurityConvergence Agent LangGraph workflow."""

import json
from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.security_convergence.models import (
    SecurityConvergenceReasoningStep,
    SecurityConvergenceState,
)
from shieldops.agents.security_convergence.prompts import SYSTEM_RESPOND, ResponseOutput
from shieldops.agents.security_convergence.tools import SecurityConvergenceToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityConvergenceToolkit | None = None


def set_toolkit(toolkit: SecurityConvergenceToolkit) -> None:
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> SecurityConvergenceToolkit:
    if _toolkit is None:
        return SecurityConvergenceToolkit()
    return _toolkit


async def collect_posture(state: SecurityConvergenceState) -> dict[str, Any]:
    """Collect security posture data"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("collect_posture", 1.0)

    step = SecurityConvergenceReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_posture",
        input_summary="Executing collect_posture",
        output_summary="Completed collect_posture",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="collect_posture",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_posture",
        "session_start": start,
    }


async def unify_signals(state: SecurityConvergenceState) -> dict[str, Any]:
    """Unify security signals across domains"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("unify_signals", 1.0)

    step = SecurityConvergenceReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="unify_signals",
        input_summary="Executing unify_signals",
        output_summary="Completed unify_signals",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="unify_signals",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "unify_signals",
    }


async def evaluate_defense(state: SecurityConvergenceState) -> dict[str, Any]:
    """Evaluate defense effectiveness"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("evaluate_defense", 1.0)

    step = SecurityConvergenceReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="evaluate_defense",
        input_summary="Executing evaluate_defense",
        output_summary="Completed evaluate_defense",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="evaluate_defense",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "evaluate_defense",
    }


async def coordinate_response(state: SecurityConvergenceState) -> dict[str, Any]:
    """Coordinate response actions"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("coordinate_response", 1.0)

    llm_summary = "Completed coordinate_response"
    try:
        response_context = json.dumps(
            {
                "current_step": state.current_step,
                "reasoning_steps": len(state.reasoning_chain),
            },
            default=str,
        )
        llm_result = cast(
            ResponseOutput,
            await llm_structured(
                system_prompt=SYSTEM_RESPOND,
                user_prompt=f"Security convergence context:\n{response_context}",
                schema=ResponseOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="coordinate_response",
            actions_count=llm_result.actions_count,
            success_rate=llm_result.success_rate,
        )
        llm_summary = (
            f"Actions: {llm_result.actions_count}, "
            f"success={llm_result.success_rate:.1f}%. {llm_result.reasoning}"
        )
    except Exception:
        logger.warning("llm_fallback", node="coordinate_response")

    step = SecurityConvergenceReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="coordinate_response",
        input_summary="Executing coordinate_response",
        output_summary=llm_summary,
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="coordinate_response",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "coordinate_response",
    }


async def finalize_evaluation(state: SecurityConvergenceState) -> dict[str, Any]:
    """Finalize convergence evaluation"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    await toolkit.record_metric("security_convergence_duration_ms", float(duration_ms))

    step = SecurityConvergenceReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="finalize_evaluation",
        input_summary="Finalizing security_convergence session",
        output_summary=f"Session complete in {duration_ms}ms",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
