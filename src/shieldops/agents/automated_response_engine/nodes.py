"""Node implementations for the Automated Response Engine."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.automated_response_engine.models import (
    AREStage,
    AutomatedResponseEngineState,
    ReasoningStep,
)
from shieldops.agents.automated_response_engine.prompts import (
    SYSTEM_ASSESS_INCIDENT,
    SYSTEM_EXECUTE_ACTIONS,
    SYSTEM_PLAN_REMEDIATION,
    SYSTEM_SELECT_PLAYBOOK,
    SYSTEM_VALIDATE_RESPONSE,
    ExecutionAnalysisOutput,
    IncidentAssessmentOutput,
    PlaybookSelectionOutput,
    RemediationPlanOutput,
    ValidationAnalysisOutput,
)
from shieldops.agents.automated_response_engine.tools import (
    AutomatedResponseEngineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AutomatedResponseEngineToolkit | None = None


def _get_toolkit() -> AutomatedResponseEngineToolkit:
    if _toolkit is None:
        return AutomatedResponseEngineToolkit()
    return _toolkit


def _step(
    state: AutomatedResponseEngineState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Create a reasoning step."""
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def assess_incident(
    state: AutomatedResponseEngineState,
) -> dict[str, Any]:
    """Assess the incoming incident and build context."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.assess_incident(state.config)
    severity = raw[0].get("severity", "unknown") if raw else "unknown"

    try:
        ctx = _json.dumps(
            {"config": state.config, "incident_count": len(raw)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ASSESS_INCIDENT,
            user_prompt=f"Incident assessment context:\n{ctx}",
            schema=IncidentAssessmentOutput,
        )
        if hasattr(llm_result, "severity"):
            logger.info("llm_enhanced", node="assess_incident")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="assess_incident")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "assess_incident",
        f"config={state.config}",
        f"assessed {len(raw)} incidents, severity={severity}",
        elapsed,
        "incident_client",
    )
    await toolkit.record_metric("incidents_assessed", float(len(raw)))

    return {
        "incident_context": raw,
        "stage": AREStage.SELECT_PLAYBOOK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_incident",
        "session_start": start,
    }


async def select_playbook(
    state: AutomatedResponseEngineState,
) -> dict[str, Any]:
    """Select response playbooks matching the incident."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    playbooks = await toolkit.select_playbook(state.incident_context)

    try:
        ctx = _json.dumps(
            {"incident_count": len(state.incident_context), "playbooks": len(playbooks)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SELECT_PLAYBOOK,
            user_prompt=f"Playbook selection context:\n{ctx}",
            schema=PlaybookSelectionOutput,
        )
        if hasattr(llm_result, "best_match"):
            logger.info("llm_enhanced", node="select_playbook")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="select_playbook")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "select_playbook",
        f"matching {len(state.incident_context)} incidents",
        f"selected {len(playbooks)} playbooks",
        elapsed,
        "playbook_store",
    )

    return {
        "selected_playbooks": playbooks,
        "stage": AREStage.PLAN_REMEDIATION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "select_playbook",
    }


async def plan_remediation(
    state: AutomatedResponseEngineState,
) -> dict[str, Any]:
    """Plan remediation actions from selected playbooks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.plan_remediation(
        state.selected_playbooks,
        state.incident_context,
    )

    try:
        ctx = _json.dumps(
            {"playbook_count": len(state.selected_playbooks), "action_count": len(actions)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PLAN_REMEDIATION,
            user_prompt=f"Remediation planning context:\n{ctx}",
            schema=RemediationPlanOutput,
        )
        if hasattr(llm_result, "actions_planned"):
            logger.info("llm_enhanced", node="plan_remediation")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="plan_remediation")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "plan_remediation",
        f"planning from {len(state.selected_playbooks)} playbooks",
        f"planned {len(actions)} remediation actions",
        elapsed,
        "action_executor",
    )
    await toolkit.record_metric("actions_planned", float(len(actions)))

    return {
        "remediation_plan": actions,
        "stage": AREStage.EXECUTE_ACTIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "plan_remediation",
    }


async def execute_actions(
    state: AutomatedResponseEngineState,
) -> dict[str, Any]:
    """Execute remediation actions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.execute_actions(state.remediation_plan)
    succeeded = sum(1 for r in results if r.get("success"))

    try:
        ctx = _json.dumps(
            {"action_count": len(state.remediation_plan), "results": results[:5]},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_EXECUTE_ACTIONS,
            user_prompt=f"Execution results context:\n{ctx}",
            schema=ExecutionAnalysisOutput,
        )
        if hasattr(llm_result, "actions_succeeded"):
            logger.info("llm_enhanced", node="execute_actions")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="execute_actions")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "execute_actions",
        f"executing {len(state.remediation_plan)} actions",
        f"{succeeded}/{len(results)} actions succeeded",
        elapsed,
        "action_executor",
    )

    return {
        "execution_results": results,
        "stage": AREStage.VALIDATE_RESPONSE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_actions",
    }


async def validate_response(
    state: AutomatedResponseEngineState,
) -> dict[str, Any]:
    """Validate that the response effectively addressed the incident."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    validations = await toolkit.validate_response(
        state.execution_results,
        state.incident_context,
    )

    try:
        ctx = _json.dumps(
            {"execution_count": len(state.execution_results), "validations": validations[:5]},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VALIDATE_RESPONSE,
            user_prompt=f"Validation context:\n{ctx}",
            schema=ValidationAnalysisOutput,
        )
        if hasattr(llm_result, "threat_neutralized"):
            logger.info("llm_enhanced", node="validate_response")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="validate_response")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "validate_response",
        f"validating {len(state.execution_results)} results",
        f"{len(validations)} validation entries",
        elapsed,
        "incident_client",
    )

    return {
        "validation_results": validations,
        "stage": AREStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_response",
    }


async def generate_report(
    state: AutomatedResponseEngineState,
) -> dict[str, Any]:
    """Generate final automated response report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "incidents_assessed": len(state.incident_context),
        "playbooks_selected": len(state.selected_playbooks),
        "actions_planned": len(state.remediation_plan),
        "actions_executed": len(state.execution_results),
        "validations": len(state.validation_results),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("response_duration_ms", float(duration_ms))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
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
