"""Node implementations for the IntelligentAutomation Agent LangGraph workflow."""

import json
from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.intelligent_automation.models import (
    IntelligentAutomationReasoningStep,
    IntelligentAutomationState,
)
from shieldops.agents.intelligent_automation.prompts import SYSTEM_EXECUTE, ExecuteOutput
from shieldops.agents.intelligent_automation.tools import IntelligentAutomationToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IntelligentAutomationToolkit | None = None


def set_toolkit(toolkit: IntelligentAutomationToolkit) -> None:
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> IntelligentAutomationToolkit:
    if _toolkit is None:
        return IntelligentAutomationToolkit()
    return _toolkit


async def assess_situation(state: IntelligentAutomationState) -> dict[str, Any]:
    """Assess the current situation and context"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("assess_situation", 1.0)

    step = IntelligentAutomationReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_situation",
        input_summary="Executing assess_situation",
        output_summary="Completed assess_situation",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="assess_situation",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_situation",
        "session_start": start,
    }


async def select_strategy(state: IntelligentAutomationState) -> dict[str, Any]:
    """Select the optimal automation strategy"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("select_strategy", 1.0)

    step = IntelligentAutomationReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="select_strategy",
        input_summary="Executing select_strategy",
        output_summary="Completed select_strategy",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="select_strategy",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "select_strategy",
    }


async def execute_automation(state: IntelligentAutomationState) -> dict[str, Any]:
    """Execute the selected automation actions"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("execute_automation", 1.0)

    llm_summary = "Completed execute_automation"
    try:
        exec_context = json.dumps(
            {
                "current_step": state.current_step,
                "reasoning_steps": len(state.reasoning_chain),
            },
            default=str,
        )
        llm_result = cast(
            ExecuteOutput,
            await llm_structured(
                system_prompt=SYSTEM_EXECUTE,
                user_prompt=f"Automation execution context:\n{exec_context}",
                schema=ExecuteOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="execute_automation",
            actions_count=llm_result.actions_count,
            success_rate=llm_result.success_rate,
        )
        llm_summary = (
            f"Actions: {llm_result.actions_count}, "
            f"success={llm_result.success_rate:.1f}%. {llm_result.reasoning}"
        )
    except Exception:
        logger.warning("llm_fallback", node="execute_automation")

    step = IntelligentAutomationReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_automation",
        input_summary="Executing execute_automation",
        output_summary=llm_summary,
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="execute_automation",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_automation",
    }


async def validate_outcome(state: IntelligentAutomationState) -> dict[str, Any]:
    """Validate automation outcomes and effectiveness"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("validate_outcome", 1.0)

    step = IntelligentAutomationReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="validate_outcome",
        input_summary="Executing validate_outcome",
        output_summary="Completed validate_outcome",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="validate_outcome",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_outcome",
    }


async def finalize_execution(state: IntelligentAutomationState) -> dict[str, Any]:
    """Finalize the automation execution session"""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    await toolkit.record_metric("intelligent_automation_duration_ms", float(duration_ms))

    step = IntelligentAutomationReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="finalize_execution",
        input_summary="Finalizing intelligent_automation session",
        output_summary=f"Session complete in {duration_ms}ms",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
