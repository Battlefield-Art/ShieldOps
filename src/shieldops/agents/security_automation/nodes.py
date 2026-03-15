"""Node implementations for the Security Automation Agent LangGraph workflow.

Each node is an async function that:
1. Uses the SecurityAutomationToolkit to perform operations
2. Uses the LLM to analyze and reason about security alerts
3. Updates the automation state with results
4. Records its reasoning step in the audit trail
"""

from datetime import UTC, datetime
from typing import Any, cast

import structlog
from pydantic import BaseModel, Field

from shieldops.agents.security_automation.models import (
    AutomationStage,
    ContainmentAction,
    ContainmentResult,
    ReasoningStep,
    SecurityAutomationState,
)
from shieldops.agents.security_automation.prompts import SYSTEM_TRIAGE
from shieldops.agents.security_automation.tools import SecurityAutomationToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()


class _TriageLLMResult(BaseModel):
    """Structured LLM output for security alert triage."""

    summary: str = Field(description="Brief summary of triage analysis")
    priority_reasoning: str = Field(description="Reasoning for alert prioritization")
    multi_stage_patterns: list[str] = Field(description="Detected multi-stage attack patterns")
    confidence: float = Field(description="Confidence in triage assessment (0.0-1.0)")


# Module-level toolkit reference, set by the runner at graph construction time.
_toolkit: SecurityAutomationToolkit | None = None


def set_toolkit(toolkit: SecurityAutomationToolkit) -> None:
    """Configure the toolkit used by all nodes. Called once at startup."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> SecurityAutomationToolkit:
    if _toolkit is None:
        return SecurityAutomationToolkit()  # Default toolkit — safe for tests
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


async def triage_alerts(state: SecurityAutomationState) -> dict[str, Any]:
    """Prioritize and filter incoming risk alerts.

    Sorts alerts by composite risk score and filters out
    those below the threshold.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "security_automation_triaging",
        request_id=state.request_id,
        alert_count=len(state.alerts),
    )

    triaged = toolkit.triage_alerts(state.alerts)

    output_summary = f"Triaged {len(state.alerts)} alerts, {len(triaged)} above threshold"

    # LLM enhancement: deeper triage analysis
    try:
        import json

        alert_summary = json.dumps(
            [
                {
                    "entity": a.entity,
                    "score": a.composite_score,
                    "tactics": a.tactics_seen,
                    "risk_level": a.risk_level if hasattr(a, "risk_level") else "unknown",
                }
                for a in state.alerts[:20]
            ],
            default=str,
        )
        llm_result = cast(
            _TriageLLMResult,
            await llm_structured(
                system_prompt=SYSTEM_TRIAGE,
                user_prompt=f"Triage these security alerts:\n{alert_summary}",
                schema=_TriageLLMResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="triage_alerts",
            llm_confidence=llm_result.confidence,
            multi_stage_patterns=len(llm_result.multi_stage_patterns),
        )
        output_summary = f"{llm_result.summary} ({len(triaged)} above threshold)"
    except Exception:
        logger.debug("llm_enhancement_skipped", node="triage_alerts")

    if triaged:
        top = triaged[0]
        output_summary += (
            f". Top: {top.entity} (score={top.composite_score}, tactics={top.tactics_seen})"
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="triage_alerts",
        input_summary=f"Triaging {len(state.alerts)} risk alerts",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="risk_triage",
    )

    return {
        "triaged_alerts": triaged,
        "stage": AutomationStage.SELECT_PLAYBOOK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "triage_alerts",
    }


async def select_playbook(state: SecurityAutomationState) -> dict[str, Any]:
    """Match the highest-priority alert to a response playbook."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    if not state.triaged_alerts:
        step = ReasoningStep(
            step_number=len(state.reasoning_chain) + 1,
            action="select_playbook",
            input_summary="No triaged alerts to process",
            output_summary="Skipped — no alerts passed triage",
            duration_ms=_elapsed_ms(start),
            tool_used=None,
        )
        return {
            "stage": AutomationStage.LEARN,
            "reasoning_chain": [*state.reasoning_chain, step],
            "current_step": "select_playbook",
        }

    # Match the top alert to a playbook
    top_alert = state.triaged_alerts[0]

    logger.info(
        "security_automation_selecting_playbook",
        request_id=state.request_id,
        entity=top_alert.entity,
        risk_score=top_alert.composite_score,
    )

    playbook = toolkit.match_playbook(top_alert)
    confidence = playbook.confidence

    output_summary = (
        f"Selected playbook: {playbook.name} "
        f"(match={playbook.match_type}, confidence={confidence:.2f})"
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="select_playbook",
        input_summary=(
            f"Matching alert entity={top_alert.entity}, tactics={top_alert.tactics_seen}"
        ),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="playbook_matcher",
    )

    return {
        "selected_playbook": playbook,
        "confidence_score": confidence,
        "stage": AutomationStage.EXECUTE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "select_playbook",
    }


async def execute_response(state: SecurityAutomationState) -> dict[str, Any]:
    """Run containment actions from the selected playbook.

    Always executes in dry-run mode unless explicitly overridden.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    if state.selected_playbook is None or not state.selected_playbook.actions:
        step = ReasoningStep(
            step_number=len(state.reasoning_chain) + 1,
            action="execute_response",
            input_summary="No playbook or actions to execute",
            output_summary="Skipped — no actions available",
            duration_ms=_elapsed_ms(start),
            tool_used=None,
        )
        return {
            "stage": AutomationStage.VALIDATE,
            "reasoning_chain": [*state.reasoning_chain, step],
            "current_step": "execute_response",
        }

    target = state.triaged_alerts[0].entity if state.triaged_alerts else "unknown"

    logger.info(
        "security_automation_executing",
        request_id=state.request_id,
        playbook=state.selected_playbook.playbook_id,
        actions=state.selected_playbook.actions,
        dry_run=state.dry_run,
    )

    results: list[ContainmentResult] = []
    for action_str in state.selected_playbook.actions:
        try:
            action = ContainmentAction(action_str)
        except ValueError:
            logger.warning("unknown_containment_action", action=action_str)
            continue

        result = await toolkit.execute_containment(
            action=action,
            target=target,
            dry_run=state.dry_run,
        )
        results.append(result)

    succeeded = sum(1 for r in results if r.success)
    output_summary = (
        f"Executed {len(results)} actions ({succeeded} succeeded), dry_run={state.dry_run}"
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_response",
        input_summary=(
            f"Running playbook {state.selected_playbook.playbook_id} "
            f"with {len(state.selected_playbook.actions)} actions"
        ),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="containment_executor",
    )

    return {
        "containment_results": results,
        "stage": AutomationStage.VALIDATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_response",
    }


async def validate_and_learn(
    state: SecurityAutomationState,
) -> dict[str, Any]:
    """Validate containment results and record learning outcome."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "security_automation_validating",
        request_id=state.request_id,
        results_count=len(state.containment_results),
    )

    # Validate
    passed = toolkit.validate_containment(state.containment_results)

    # Record learning if we have alert and playbook context
    learning = None
    if state.triaged_alerts and state.selected_playbook:
        learning = toolkit.record_learning(
            alert=state.triaged_alerts[0],
            playbook=state.selected_playbook,
            results=state.containment_results,
            accepted=passed,
            feedback="auto-validated" if passed else "containment-incomplete",
        )

    output_summary = (
        f"Validation {'PASSED' if passed else 'FAILED'}. "
        f"Learning outcome: {'accepted' if passed else 'rejected'}"
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="validate_and_learn",
        input_summary=(f"Validating {len(state.containment_results)} containment results"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="validator",
    )

    return {
        "validation_passed": passed,
        "learning_outcome": learning,
        "stage": AutomationStage.LEARN,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_and_learn",
    }
