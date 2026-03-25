"""Node implementations for the Runbook Automation Agent LangGraph workflow."""

import json
import time
from typing import Any, cast

import structlog

from shieldops.agents.runbook_automation.models import (
    ApprovalRequest,
    AutomationStage,
    ExecutionStep,
    OutcomeVerification,
    PreconditionCheck,
    ReasoningStep,
    Runbook,
    RunbookAutomationState,
    StepResult,
)
from shieldops.agents.runbook_automation.prompts import (
    SYSTEM_EXECUTE,
    SYSTEM_SELECT,
    SYSTEM_VERIFY,
    ExecutionPlanOutput,
    OutcomeAnalysisOutput,
    RunbookSelectionOutput,
)
from shieldops.agents.runbook_automation.tools import RunbookAutomationToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: RunbookAutomationToolkit | None = None


def set_toolkit(toolkit: RunbookAutomationToolkit) -> None:
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> RunbookAutomationToolkit:
    if _toolkit is None:
        return RunbookAutomationToolkit()
    return _toolkit


# ---------------------------------------------------------------------------
# Node: select_runbook
# ---------------------------------------------------------------------------


async def select_runbook(state: RunbookAutomationState) -> dict[str, Any]:
    """Select and bind a runbook from the library."""
    start = time.time()
    toolkit = _get_toolkit()

    runbook_name = state.stats.get("runbook_name", "restart_service")
    target_service = state.stats.get("target_service", "unknown")

    rb_data = await toolkit.select_runbook(runbook_name, target_service)

    if "error" in rb_data:
        return {
            "error": rb_data["error"],
            "stage": AutomationStage.SELECT_RUNBOOK,
            "current_step": "select_runbook",
        }

    # LLM-enhanced selection reasoning
    llm_detail = "Runbook selected from library"
    try:
        context = json.dumps(
            {"runbook": runbook_name, "target": target_service, "risk": rb_data["risk_level"]},
            default=str,
        )
        llm_result = cast(
            RunbookSelectionOutput,
            await llm_structured(
                system_prompt=SYSTEM_SELECT,
                user_prompt=f"Runbook selection context:\n{context}",
                schema=RunbookSelectionOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="select_runbook",
            rationale=llm_result.rationale,
        )
        llm_detail = (
            f"Selected '{llm_result.selected_runbook}': "
            f"{llm_result.rationale}. Risk: {llm_result.risk_assessment}"
        )
    except Exception:
        logger.warning("llm_fallback", node="select_runbook")

    verifications = rb_data.pop("verifications", [])
    runbook = Runbook(**{k: v for k, v in rb_data.items() if k != "verifications"})

    step = ReasoningStep(
        step="select_runbook",
        detail=llm_detail,
        confidence=0.9,
        metadata={"runbook_name": runbook_name, "target": target_service},
    )

    return {
        "runbook": runbook,
        "stage": AutomationStage.VALIDATE_PRECONDITIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "select_runbook",
        "session_start": start,
        "stats": {
            **state.stats,
            "verifications": verifications,
        },
    }


# ---------------------------------------------------------------------------
# Node: validate_preconditions
# ---------------------------------------------------------------------------


async def validate_preconditions(state: RunbookAutomationState) -> dict[str, Any]:
    """Validate all preconditions before execution."""
    start = time.time()
    toolkit = _get_toolkit()

    runbook = state.runbook
    if not runbook:
        return {"error": "No runbook selected", "current_step": "validate_preconditions"}

    raw_checks = await toolkit.validate_preconditions(runbook.id, runbook.target_service)
    checks = [PreconditionCheck(**c) for c in raw_checks]

    blocking_failures = [c for c in checks if c.blocking and not c.passed]
    all_passed = len(blocking_failures) == 0

    await toolkit.record_metric("precondition_checks", float(len(checks)))

    step = ReasoningStep(
        step="validate_preconditions",
        detail=(
            f"{len(checks)} checks run, {len(blocking_failures)} blocking failures"
            if not all_passed
            else f"All {len(checks)} preconditions passed"
        ),
        confidence=1.0 if all_passed else 0.3,
        metadata={"checks": len(checks), "passed": all_passed},
    )

    duration_ms = (time.time() - start) * 1000
    return {
        "precondition_checks": checks,
        "stage": AutomationStage.REQUEST_APPROVAL,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_preconditions",
        "error": (
            f"Blocking preconditions failed: {[c.check_name for c in blocking_failures]}"
            if not all_passed
            else state.error
        ),
        "stats": {**state.stats, "precondition_duration_ms": duration_ms},
    }


# ---------------------------------------------------------------------------
# Node: request_approval
# ---------------------------------------------------------------------------


async def request_approval(state: RunbookAutomationState) -> dict[str, Any]:
    """Request approval for runbook execution when required."""
    start = time.time()
    toolkit = _get_toolkit()

    runbook = state.runbook
    if not runbook:
        return {"error": "No runbook selected", "current_step": "request_approval"}

    if not runbook.approval_required:
        step = ReasoningStep(
            step="request_approval",
            detail="Approval not required for this runbook",
            confidence=1.0,
            metadata={"skipped": True},
        )
        return {
            "approval": ApprovalRequest(
                runbook_id=runbook.id,
                status="approved",
                reason="approval_not_required",
            ),
            "stage": AutomationStage.EXECUTE_STEPS,
            "reasoning_chain": [*state.reasoning_chain, step],
            "current_step": "request_approval",
        }

    raw_approval = await toolkit.request_approval(
        runbook_id=runbook.id,
        requester=state.tenant_id or "system",
        risk_level=runbook.risk_level,
    )
    approval = ApprovalRequest(**raw_approval)

    approved = approval.status == "approved"
    duration_ms = (time.time() - start) * 1000

    step = ReasoningStep(
        step="request_approval",
        detail=f"Approval {approval.status} by {approval.approver}: {approval.reason}",
        confidence=1.0 if approved else 0.0,
        metadata={"approver": approval.approver, "status": approval.status},
    )

    return {
        "approval": approval,
        "stage": AutomationStage.EXECUTE_STEPS if approved else AutomationStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "request_approval",
        "error": None if approved else f"Approval denied: {approval.reason}",
        "stats": {**state.stats, "approval_duration_ms": duration_ms},
    }


# ---------------------------------------------------------------------------
# Node: execute_steps
# ---------------------------------------------------------------------------


async def execute_steps(state: RunbookAutomationState) -> dict[str, Any]:
    """Execute all runbook steps sequentially with rollback on failure."""
    start = time.time()
    toolkit = _get_toolkit()

    runbook = state.runbook
    if not runbook:
        return {"error": "No runbook selected", "current_step": "execute_steps"}

    # LLM-enhanced execution planning
    llm_detail = "Executing steps sequentially"
    try:
        plan_ctx = json.dumps(
            {
                "steps": [s.get("name") for s in runbook.steps],
                "risk_level": runbook.risk_level,
                "target": runbook.target_service,
            },
            default=str,
        )
        llm_result = cast(
            ExecutionPlanOutput,
            await llm_structured(
                system_prompt=SYSTEM_EXECUTE,
                user_prompt=f"Execution plan context:\n{plan_ctx}",
                schema=ExecutionPlanOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="execute_steps",
            strategy=llm_result.strategy,
            risk=llm_result.estimated_risk,
        )
        llm_detail = (
            f"Strategy: {llm_result.strategy}, "
            f"risk={llm_result.estimated_risk:.1f}. {llm_result.reasoning}"
        )
    except Exception:
        logger.warning("llm_fallback", node="execute_steps")

    executed: list[ExecutionStep] = []
    all_succeeded = True

    for idx, step_def in enumerate(runbook.steps):
        raw_result = await toolkit.execute_step(
            runbook_id=runbook.id,
            step_number=idx + 1,
            step_def=step_def,
            target_service=runbook.target_service,
        )
        ex_step = ExecutionStep(**raw_result)
        executed.append(ex_step)

        if ex_step.result == StepResult.FAILED:
            all_succeeded = False
            logger.warning(
                "runbook_automation.step_failed",
                step=ex_step.step_name,
                output=ex_step.output,
            )
            break

    rollback_triggered = False
    if not all_succeeded:
        rollback_results = await toolkit.rollback_steps([s.model_dump() for s in executed])
        rollback_triggered = len(rollback_results) > 0
        for rb_res in rollback_results:
            for ex in executed:
                if ex.step_name == rb_res.get("step_name"):
                    ex.result = StepResult.ROLLED_BACK

    duration_ms = (time.time() - start) * 1000
    await toolkit.record_metric("execution_duration_ms", duration_ms)

    step = ReasoningStep(
        step="execute_steps",
        detail=llm_detail,
        confidence=0.95 if all_succeeded else 0.4,
        metadata={
            "steps_executed": len(executed),
            "all_succeeded": all_succeeded,
            "rollback_triggered": rollback_triggered,
        },
    )

    return {
        "execution_steps": executed,
        "rollback_triggered": rollback_triggered,
        "stage": AutomationStage.VERIFY_OUTCOME,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_steps",
        "stats": {
            **state.stats,
            "execution_duration_ms": duration_ms,
            "steps_executed": len(executed),
            "all_succeeded": all_succeeded,
        },
    }


# ---------------------------------------------------------------------------
# Node: verify_outcome
# ---------------------------------------------------------------------------


async def verify_outcome(state: RunbookAutomationState) -> dict[str, Any]:
    """Verify the outcome of runbook execution."""
    start = time.time()
    toolkit = _get_toolkit()

    runbook = state.runbook
    if not runbook:
        return {"error": "No runbook selected", "current_step": "verify_outcome"}

    verifications_def = state.stats.get("verifications", [])
    raw_results = await toolkit.verify_outcome(runbook.id, verifications_def)
    verifications = [OutcomeVerification(**v) for v in raw_results]

    all_passed = all(v.passed for v in verifications)

    # LLM-enhanced outcome analysis
    llm_detail = "Outcome verification complete"
    try:
        verify_ctx = json.dumps(
            {
                "verifications": [
                    {"name": v.verification_name, "passed": v.passed, "actual": v.actual}
                    for v in verifications
                ],
                "rollback_triggered": state.rollback_triggered,
                "steps_executed": len(state.execution_steps),
            },
            default=str,
        )
        llm_result = cast(
            OutcomeAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_VERIFY,
                user_prompt=f"Outcome verification context:\n{verify_ctx}",
                schema=OutcomeAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="verify_outcome",
            success=llm_result.overall_success,
            confidence=llm_result.confidence,
        )
        llm_detail = (
            f"Success={llm_result.overall_success}, "
            f"confidence={llm_result.confidence:.2f}. {llm_result.summary}"
        )
    except Exception:
        logger.warning("llm_fallback", node="verify_outcome")

    duration_ms = (time.time() - start) * 1000
    await toolkit.record_metric("verification_duration_ms", duration_ms)

    step = ReasoningStep(
        step="verify_outcome",
        detail=llm_detail,
        confidence=0.95 if all_passed else 0.5,
        metadata={
            "verifications": len(verifications),
            "all_passed": all_passed,
        },
    )

    return {
        "outcome_verifications": verifications,
        "stage": AutomationStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "verify_outcome",
        "stats": {
            **state.stats,
            "verification_duration_ms": duration_ms,
            "all_verifications_passed": all_passed,
        },
    }


# ---------------------------------------------------------------------------
# Node: report
# ---------------------------------------------------------------------------


async def report(state: RunbookAutomationState) -> dict[str, Any]:
    """Finalize the runbook execution and produce a report."""
    toolkit = _get_toolkit()

    duration_ms = 0.0
    if state.session_start:
        duration_ms = (time.time() - state.session_start) * 1000

    succeeded = (
        not state.rollback_triggered
        and state.stats.get("all_succeeded", False)
        and state.stats.get("all_verifications_passed", False)
    )

    await toolkit.record_metric("runbook_automation_duration_ms", duration_ms)
    await toolkit.record_metric("runbook_automation_success", 1.0 if succeeded else 0.0)

    step = ReasoningStep(
        step="report",
        detail=(
            f"Runbook '{state.runbook.name if state.runbook else 'unknown'}' "
            f"{'completed successfully' if succeeded else 'finished with issues'} "
            f"in {duration_ms:.0f}ms"
        ),
        confidence=0.95 if succeeded else 0.5,
        metadata={
            "succeeded": succeeded,
            "duration_ms": duration_ms,
            "rollback_triggered": state.rollback_triggered,
        },
    )

    return {
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
        "stage": AutomationStage.REPORT,
        "stats": {
            **state.stats,
            "total_duration_ms": duration_ms,
            "succeeded": succeeded,
        },
    }
