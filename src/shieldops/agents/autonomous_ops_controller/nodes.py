"""Node implementations for the Autonomous Ops Controller LangGraph workflow.

Each node is an async function that:
1. Queries fleet systems via the toolkit
2. Uses the LLM to analyze and reason about data
3. Updates the AOC state with findings
4. Records its reasoning step in the audit trail
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.autonomous_ops_controller.models import (
    AOCStage,
    AutonomousOpsControllerState,
    ExecutionStatus,
    FleetAssessment,
    OperationPlan,
    ReasoningStep,
    TaskDispatch,
)
from shieldops.agents.autonomous_ops_controller.prompts import (
    SYSTEM_ASSESS_FLEET,
    SYSTEM_DISPATCH_TASKS,
    SYSTEM_EVALUATE_OUTCOMES,
    SYSTEM_MONITOR_EXECUTION,
    SYSTEM_PLAN_OPERATIONS,
    DispatchAnalysis,
    ExecutionAnalysis,
    FleetAssessmentAnalysis,
    OperationPlanAnalysis,
    OutcomeAnalysis,
)
from shieldops.agents.autonomous_ops_controller.tools import (
    AutonomousOpsControllerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit, set by runner at startup.
_toolkit: AutonomousOpsControllerToolkit | None = None


def _get_toolkit() -> AutonomousOpsControllerToolkit:
    if _toolkit is None:
        return AutonomousOpsControllerToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# ---- Node: assess_fleet ----


async def assess_fleet(
    state: AutonomousOpsControllerState,
) -> dict[str, Any]:
    """Assess current health and capacity of the agent fleet."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "aoc_assessing_fleet",
        request_id=state.request_id,
    )

    assessment = await toolkit.assess_fleet(
        tenant_id=state.tenant_id,
    )

    output_summary = (
        f"Fleet: {assessment.total_agents} agents, "
        f"{assessment.healthy_count} healthy, "
        f"status={assessment.fleet_status.value}."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "total_agents": assessment.total_agents,
                "healthy": assessment.healthy_count,
                "degraded": assessment.degraded_count,
                "offline": assessment.offline_count,
                "status": assessment.fleet_status.value,
                "utilization": assessment.capacity_utilization,
            },
            default=str,
        )
        llm_result = cast(
            FleetAssessmentAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_ASSESS_FLEET,
                user_prompt=f"Fleet assessment results:\n{ctx}",
                schema=FleetAssessmentAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Status: {llm_result.health_status}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_fleet",
        )

    step = ReasoningStep(
        step_number=1,
        action="assess_fleet",
        input_summary="Assessing agent fleet health and capacity",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="fleet_manager",
    )

    return {
        "fleet_assessment": [assessment.model_dump()],
        "fleet_health": assessment.fleet_status.value,
        "stage": AOCStage.PLAN_OPERATIONS,
        "session_start": start,
        "reasoning_chain": [step],
        "current_step": "assess_fleet",
    }


# ---- Node: plan_operations ----


async def plan_operations(
    state: AutonomousOpsControllerState,
) -> dict[str, Any]:
    """Plan operations based on fleet assessment."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessment_data = state.fleet_assessment[0] if state.fleet_assessment else {}
    assessment = FleetAssessment.model_validate(assessment_data)

    logger.info(
        "aoc_planning_operations",
        request_id=state.request_id,
        fleet_status=assessment.fleet_status.value,
    )

    plans = await toolkit.plan_operations(assessment, config=state.config)

    output_summary = (
        f"Planned {len(plans)} operations for {assessment.healthy_count} healthy agents."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "plans": len(plans),
                "operation_types": [p.operation_type.value for p in plans],
                "priorities": [p.priority for p in plans],
                "total_agents": sum(len(p.target_agents) for p in plans),
            },
            default=str,
        )
        llm_result = cast(
            OperationPlanAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_PLAN_OPERATIONS,
                user_prompt=f"Operation planning results:\n{ctx}",
                schema=OperationPlanAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(plans)} operations."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="plan_operations",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="plan_operations",
        input_summary=(f"Planning operations for fleet ({assessment.fleet_status.value})"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="task_scheduler",
    )

    return {
        "operation_plans": [p.model_dump() for p in plans],
        "stage": AOCStage.DISPATCH_TASKS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "plan_operations",
    }


# ---- Node: dispatch_tasks ----


async def dispatch_tasks(
    state: AutonomousOpsControllerState,
) -> dict[str, Any]:
    """Dispatch tasks to agents based on operation plans."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    plans = [OperationPlan.model_validate(p) for p in state.operation_plans]

    logger.info(
        "aoc_dispatching_tasks",
        request_id=state.request_id,
        plan_count=len(plans),
    )

    dispatches = await toolkit.dispatch_tasks(plans)

    output_summary = f"Dispatched {len(dispatches)} tasks from {len(plans)} operation plans."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "plans": len(plans),
                "tasks_dispatched": len(dispatches),
                "operation_types": [d.operation_type.value for d in dispatches],
                "agents": list({d.agent_id for d in dispatches}),
            },
            default=str,
        )
        llm_result = cast(
            DispatchAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_DISPATCH_TASKS,
                user_prompt=f"Task dispatch results:\n{ctx}",
                schema=DispatchAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Coverage: {llm_result.coverage_assessment}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="dispatch_tasks",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="dispatch_tasks",
        input_summary=f"Dispatching tasks for {len(plans)} operations",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="task_dispatcher",
    )

    return {
        "dispatched_tasks": [d.model_dump() for d in dispatches],
        "tasks_dispatched": len(dispatches),
        "stage": AOCStage.MONITOR_EXECUTION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "dispatch_tasks",
    }


# ---- Node: monitor_execution ----


async def monitor_execution(
    state: AutonomousOpsControllerState,
) -> dict[str, Any]:
    """Monitor execution of dispatched tasks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    tasks = [TaskDispatch.model_validate(t) for t in state.dispatched_tasks]

    logger.info(
        "aoc_monitoring_execution",
        request_id=state.request_id,
        task_count=len(tasks),
    )

    statuses = await toolkit.monitor_execution(tasks)

    completed = sum(1 for s in statuses if s.status == "completed")
    failed = sum(1 for s in statuses if s.status in ("failed", "timeout"))

    output_summary = f"Monitored {len(statuses)} tasks. {completed} completed, {failed} failed."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "total": len(statuses),
                "completed": completed,
                "failed": failed,
                "statuses": [s.status for s in statuses],
                "avg_duration": (sum(s.duration_ms for s in statuses) // max(len(statuses), 1)),
            },
            default=str,
        )
        llm_result = cast(
            ExecutionAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_MONITOR_EXECUTION,
                user_prompt=f"Execution monitoring results:\n{ctx}",
                schema=ExecutionAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Health: {llm_result.overall_health}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="monitor_execution",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="monitor_execution",
        input_summary=f"Monitoring {len(tasks)} dispatched tasks",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="execution_monitor",
    )

    return {
        "execution_statuses": [s.model_dump() for s in statuses],
        "tasks_succeeded": completed,
        "stage": AOCStage.EVALUATE_OUTCOMES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "monitor_execution",
    }


# ---- Node: evaluate_outcomes ----


async def evaluate_outcomes(
    state: AutonomousOpsControllerState,
) -> dict[str, Any]:
    """Evaluate outcomes of completed operations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    statuses = [ExecutionStatus.model_validate(s) for s in state.execution_statuses]
    plans = [OperationPlan.model_validate(p) for p in state.operation_plans]

    logger.info(
        "aoc_evaluating_outcomes",
        request_id=state.request_id,
        status_count=len(statuses),
    )

    evaluations = await toolkit.evaluate_outcomes(statuses, plans)

    overall_rate = round(
        sum(e.success_rate for e in evaluations) / max(len(evaluations), 1),
        3,
    )

    output_summary = (
        f"Evaluated {len(evaluations)} operations. Overall success rate: {overall_rate:.1%}."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "evaluations": len(evaluations),
                "overall_success_rate": overall_rate,
                "findings": [f for e in evaluations for f in e.key_findings],
            },
            default=str,
        )
        llm_result = cast(
            OutcomeAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_EVALUATE_OUTCOMES,
                user_prompt=f"Outcome evaluation results:\n{ctx}",
                schema=OutcomeAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Rate: {overall_rate:.1%}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="evaluate_outcomes",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="evaluate_outcomes",
        input_summary=f"Evaluating outcomes of {len(statuses)} tasks",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="outcome_evaluator",
    )

    return {
        "outcome_evaluations": [e.model_dump() for e in evaluations],
        "success_rate": overall_rate,
        "stage": AOCStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "evaluate_outcomes",
    }


# ---- Node: generate_report ----


async def generate_report(
    state: AutonomousOpsControllerState,
) -> dict[str, Any]:
    """Final reporting node -- summarize the autonomous ops cycle."""
    start = datetime.now(UTC)

    session_duration_ms = 0
    if state.session_start:
        session_duration_ms = _elapsed_ms(state.session_start)

    output_summary = (
        f"AOC cycle complete. "
        f"Fleet: {state.fleet_health}, "
        f"{len(state.operation_plans)} plans, "
        f"{state.tasks_dispatched} tasks dispatched, "
        f"{state.tasks_succeeded} succeeded, "
        f"rate={state.success_rate:.1%}. "
        f"Duration: {session_duration_ms}ms."
    )

    logger.info(
        "aoc_report",
        request_id=state.request_id,
        summary=output_summary,
    )

    report = {
        "request_id": state.request_id,
        "tenant_id": state.tenant_id,
        "fleet_health": state.fleet_health,
        "operations_planned": len(state.operation_plans),
        "tasks_dispatched": state.tasks_dispatched,
        "tasks_succeeded": state.tasks_succeeded,
        "success_rate": state.success_rate,
        "outcome_evaluations": len(state.outcome_evaluations),
        "duration_ms": session_duration_ms,
        "summary": output_summary,
    }

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary="Generating final autonomous ops report",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": session_duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
