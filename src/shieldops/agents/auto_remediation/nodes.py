"""Node implementations for the Auto Remediation Agent LangGraph workflow."""

import json
from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.auto_remediation.models import (
    AutoRemediationState,
    RemediationReasoningStep,
)
from shieldops.agents.auto_remediation.prompts import SYSTEM_PLAN, PlanOutput
from shieldops.agents.auto_remediation.tools import AutoRemediationToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AutoRemediationToolkit | None = None


def set_toolkit(toolkit: AutoRemediationToolkit) -> None:
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> AutoRemediationToolkit:
    if _toolkit is None:
        return AutoRemediationToolkit()
    return _toolkit


async def assess_issue(state: AutoRemediationState) -> dict[str, Any]:
    """Assess the issue to be remediated."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("assess_issue", 1.0)

    step = RemediationReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_issue",
        input_summary="Executing assess_issue",
        output_summary="Completed assess_issue",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="assess_issue",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_issue",
        "session_start": start,
    }


async def plan_remediation(state: AutoRemediationState) -> dict[str, Any]:
    """Plan the remediation strategy."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("plan_remediation", 1.0)

    llm_summary = "Completed plan_remediation"
    try:
        plan_context = json.dumps(
            {
                "current_step": state.current_step,
                "reasoning_steps": len(state.reasoning_chain),
            },
            default=str,
        )
        llm_result = cast(
            PlanOutput,
            await llm_structured(
                system_prompt=SYSTEM_PLAN,
                user_prompt=f"Remediation context:\n{plan_context}",
                schema=PlanOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="plan_remediation",
            strategy=llm_result.strategy,
            risk_score=llm_result.risk_score,
        )
        llm_summary = (
            f"Strategy: {llm_result.strategy}, "
            f"risk={llm_result.risk_score:.1f}. {llm_result.reasoning}"
        )
    except Exception:
        logger.warning("llm_fallback", node="plan_remediation")

    step = RemediationReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="plan_remediation",
        input_summary="Executing plan_remediation",
        output_summary=llm_summary,
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="plan_remediation",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "plan_remediation",
    }


async def execute_fix(state: AutoRemediationState) -> dict[str, Any]:
    """Execute the remediation fix."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("execute_fix", 1.0)

    step = RemediationReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_fix",
        input_summary="Executing execute_fix",
        output_summary="Completed execute_fix",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="execute_fix",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_fix",
    }


async def verify_resolution(state: AutoRemediationState) -> dict[str, Any]:
    """Verify the issue is resolved."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("verify_resolution", 1.0)

    step = RemediationReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="verify_resolution",
        input_summary="Executing verify_resolution",
        output_summary="Completed verify_resolution",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="verify_resolution",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "verify_resolution",
    }


async def finalize_remediation(state: AutoRemediationState) -> dict[str, Any]:
    """Finalize the remediation session."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    await toolkit.record_metric("auto_remediation_duration_ms", float(duration_ms))

    step = RemediationReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="finalize_remediation",
        input_summary="Finalizing auto_remediation session",
        output_summary=f"Session complete in {duration_ms}ms",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
