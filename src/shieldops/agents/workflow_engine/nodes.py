"""Node implementations for the Workflow Engine LangGraph workflow."""

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.workflow_engine.models import (
    ReasoningStep,
    StepType,
    WorkflowEngineState,
    WorkflowResult,
    WorkflowStatus,
)
from shieldops.agents.workflow_engine.prompts import (
    SYSTEM_EXECUTE,
    SYSTEM_GATE,
    SYSTEM_REPORT,
    SYSTEM_VALIDATE,
    ExecutionPlanOutput,
    GateDecisionOutput,
    ReportOutput,
    ValidationOutput,
)
from shieldops.agents.workflow_engine.tools import WorkflowEngineToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: WorkflowEngineToolkit | None = None


def set_toolkit(toolkit: WorkflowEngineToolkit) -> None:
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> WorkflowEngineToolkit:
    if _toolkit is None:
        return WorkflowEngineToolkit()
    return _toolkit


async def load_workflow(state: WorkflowEngineState) -> dict[str, Any]:
    """Load workflow definition from the library."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("load_workflow", 1.0)

    definition = await toolkit.load_workflow(state.workflow_name)

    if definition is None:
        step = ReasoningStep(
            step_number=len(state.reasoning_chain) + 1,
            action="load_workflow",
            input_summary=f"Loading workflow '{state.workflow_name}'",
            output_summary=f"Workflow '{state.workflow_name}' not found in library",
            duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
            tool_used="load_workflow",
        )
        return {
            "reasoning_chain": [*state.reasoning_chain, step],
            "current_step": "load_workflow",
            "error": f"Workflow '{state.workflow_name}' not found",
            "session_start": start,
        }

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="load_workflow",
        input_summary=f"Loading workflow '{state.workflow_name}'",
        output_summary=f"Loaded workflow with {len(definition.steps)} steps",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="load_workflow",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "load_workflow",
        "workflow_definition": definition,
        "session_start": start,
    }


async def validate_workflow(state: WorkflowEngineState) -> dict[str, Any]:
    """Validate the loaded workflow definition."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("validate_workflow", 1.0)

    if state.workflow_definition is None:
        step = ReasoningStep(
            step_number=len(state.reasoning_chain) + 1,
            action="validate_workflow",
            input_summary="Validating workflow definition",
            output_summary="No workflow definition to validate",
            duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
            tool_used="validate_workflow",
        )
        return {
            "reasoning_chain": [*state.reasoning_chain, step],
            "current_step": "validate",
            "validation_passed": False,
            "validation_errors": ["No workflow definition loaded"],
            "error": "No workflow definition loaded",
        }

    is_valid, errors = await toolkit.validate_workflow(state.workflow_definition)

    # LLM enhancement: deeper validation analysis
    try:
        ctx = _json.dumps(
            {
                "workflow": state.workflow_definition.model_dump(),
                "trigger_data": state.trigger_data,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VALIDATE,
            user_prompt=f"Validate this workflow:\n{ctx}",
            schema=ValidationOutput,
        )
        if llm_result and not llm_result.is_valid:
            errors.extend(llm_result.recommendations)
            is_valid = False
        logger.info(
            "llm_enhanced",
            node="validate_workflow",
            risk_level=getattr(llm_result, "risk_level", "unknown"),
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="validate_workflow")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="validate_workflow",
        input_summary=f"Validating '{state.workflow_definition.name}'",
        output_summary=f"Validation {'passed' if is_valid else 'failed'} with {len(errors)} errors",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="validate_workflow",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate",
        "validation_passed": is_valid,
        "validation_errors": errors,
        "error": None if is_valid else f"Validation failed: {'; '.join(errors)}",
    }


async def execute_steps(state: WorkflowEngineState) -> dict[str, Any]:
    """Execute all workflow steps sequentially."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("execute_steps", 1.0)

    if state.workflow_definition is None:
        return {
            "current_step": "execute_steps",
            "error": "No workflow definition to execute",
        }

    # LLM enhancement: plan execution order
    try:
        ctx = _json.dumps(
            {"steps": state.workflow_definition.steps, "trigger": state.trigger_data},
            default=str,
        )
        await llm_structured(
            system_prompt=SYSTEM_EXECUTE,
            user_prompt=f"Plan execution for:\n{ctx}",
            schema=ExecutionPlanOutput,
        )
        logger.info("llm_enhanced", node="execute_steps")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="execute_steps")

    executed: list[Any] = []
    workflow_id = state.workflow_definition.id

    for step_def in state.workflow_definition.steps:
        result = await toolkit.execute_step(step_def, workflow_id)
        executed.append(result)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_steps",
        input_summary=f"Executing {len(state.workflow_definition.steps)} steps",
        output_summary=f"Executed {len(executed)} steps",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="execute_step",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_steps",
        "executed_steps": executed,
    }


async def check_gates(state: WorkflowEngineState) -> dict[str, Any]:
    """Check and resolve approval gates for paused steps."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("check_gates", 1.0)

    if state.workflow_definition is None:
        return {
            "current_step": "check_gates",
            "error": "No workflow definition for gate checks",
        }

    gates = []
    for step in state.executed_steps:
        if step.step_type == StepType.APPROVAL_GATE:
            # LLM enhancement: evaluate gate decision
            try:
                ctx = _json.dumps(
                    {
                        "step": step.model_dump(),
                        "workflow": state.workflow_definition.name,
                        "trigger": state.trigger_data,
                    },
                    default=str,
                )
                llm_result = await llm_structured(
                    system_prompt=SYSTEM_GATE,
                    user_prompt=f"Evaluate approval gate:\n{ctx}",
                    schema=GateDecisionOutput,
                )
                logger.info(
                    "llm_enhanced",
                    node="check_gates",
                    confidence=getattr(llm_result, "confidence", 0),
                )
            except Exception:
                logger.debug("llm_enhancement_skipped", node="check_gates")

            gate = await toolkit.check_approval_gate(step, state.workflow_definition.id)
            gates.append(gate)

            # Mark step as completed after approval
            step.status = WorkflowStatus.COMPLETED
            step.output = f"Approved by {gate.approver}: {gate.reason}"

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="check_gates",
        input_summary=f"Checking gates for {len(state.executed_steps)} steps",
        output_summary=f"Resolved {len(gates)} approval gates",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="check_approval_gate",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "check_gates",
        "pending_gates": gates,
    }


async def finalize_workflow(state: WorkflowEngineState) -> dict[str, Any]:
    """Finalize workflow execution and compute result."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("finalize_workflow", 1.0)

    completed = sum(1 for s in state.executed_steps if s.status == WorkflowStatus.COMPLETED)
    total = len(state.executed_steps)
    failed = sum(1 for s in state.executed_steps if s.status == WorkflowStatus.FAILED)

    if state.error or failed > 0:
        overall_status = WorkflowStatus.FAILED
    elif completed == total and total > 0:
        overall_status = WorkflowStatus.COMPLETED
    else:
        overall_status = WorkflowStatus.COMPLETED

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    result = WorkflowResult(
        id=f"result-{state.session_id}",
        workflow_id=(state.workflow_definition.id if state.workflow_definition else ""),
        status=overall_status,
        steps_completed=completed,
        total_steps=total,
        duration_min=round(duration_ms / 60000, 2),
        output={
            "steps": [s.model_dump() for s in state.executed_steps],
            "gates": [g.model_dump() for g in state.pending_gates],
        },
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="finalize_workflow",
        input_summary=f"Finalizing workflow ({completed}/{total} completed)",
        output_summary=f"Workflow {overall_status.value}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="finalize_workflow",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "finalize",
        "result": result,
        "session_duration_ms": duration_ms,
    }


async def report_workflow(state: WorkflowEngineState) -> dict[str, Any]:
    """Generate a summary report of the workflow execution."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric("report_workflow", 1.0)

    # LLM enhancement: generate executive report
    try:
        ctx = _json.dumps(
            {
                "result": state.result.model_dump() if state.result else {},
                "reasoning_chain": [r.model_dump() for r in state.reasoning_chain],
                "workflow_name": state.workflow_name,
                "trigger_data": state.trigger_data,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate workflow execution report:\n{ctx}",
            schema=ReportOutput,
        )
        logger.info(
            "llm_enhanced",
            node="report_workflow",
            summary_length=len(getattr(llm_result, "summary", "")),
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="report_workflow")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report_workflow",
        input_summary="Generating execution report",
        output_summary="Report generated",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="report_workflow",
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "report",
    }
