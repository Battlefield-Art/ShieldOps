"""Tool functions for the Autonomous Ops Controller.

Bridges fleet assessment, operation planning, task dispatch,
execution monitoring, and outcome evaluation to the
LangGraph nodes.
"""

from __future__ import annotations

import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.autonomous_ops_controller.models import (
    ExecutionStatus,
    FleetAssessment,
    FleetStatus,
    OperationPlan,
    OperationType,
    OutcomeEvaluation,
    TaskDispatch,
)

logger = structlog.get_logger()


class AutonomousOpsControllerToolkit:
    """Tools for the autonomous ops controller agent.

    Injected into nodes at graph construction time to
    decouple agent logic from fleet infrastructure.
    """

    def __init__(
        self,
        fleet_manager: Any | None = None,
        task_scheduler: Any | None = None,
        execution_monitor: Any | None = None,
        metrics_collector: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._fleet_manager = fleet_manager
        self._task_scheduler = task_scheduler
        self._execution_monitor = execution_monitor
        self._metrics_collector = metrics_collector
        self._policy_engine = policy_engine
        self._repository = repository
        self._metrics: list[dict[str, Any]] = []

    # ---- Fleet Assessment ----

    async def assess_fleet(
        self,
        tenant_id: str = "",
    ) -> FleetAssessment:
        """Assess current health and capacity of the agent fleet.

        Args:
            tenant_id: Tenant for scoping queries.

        Returns:
            FleetAssessment object.
        """
        now = datetime.now(UTC)

        if self._fleet_manager is not None:
            try:
                raw = await self._fleet_manager.assess(tenant_id=tenant_id)
                return FleetAssessment(
                    assessment_id=raw.get("id", f"fa-{uuid4().hex[:8]}"),
                    total_agents=raw.get("total", 0),
                    healthy_count=raw.get("healthy", 0),
                    degraded_count=raw.get("degraded", 0),
                    offline_count=raw.get("offline", 0),
                    fleet_status=FleetStatus(raw.get("status", "healthy")),
                    capacity_utilization=raw.get("utilization", 0.0),
                    available_capacity=raw.get("available", 0.0),
                    agent_statuses=raw.get("agents", []),
                    assessed_at=now,
                )
            except Exception as e:
                logger.error(
                    "aoc_fleet_assessment_failed",
                    error=str(e),
                )

        # Mock fleet data
        total = random.randint(20, 80)  # noqa: S311
        healthy = int(total * random.uniform(0.7, 0.95))  # noqa: S311
        degraded = random.randint(1, max(1, total - healthy - 1))  # noqa: S311
        offline = total - healthy - degraded
        utilization = round(random.uniform(0.3, 0.85), 2)  # noqa: S311

        if healthy / total > 0.8:
            status = FleetStatus.HEALTHY
        elif healthy / total > 0.5:
            status = FleetStatus.DEGRADED
        else:
            status = FleetStatus.CRITICAL

        agent_statuses = []
        agent_types = [
            "threat_hunter",
            "vulnerability_scanner",
            "incident_responder",
            "compliance_checker",
            "patch_manager",
            "intel_collector",
        ]
        for _unused_i in range(total):
            agent_statuses.append(
                {
                    "agent_id": f"agent-{uuid4().hex[:6]}",
                    "agent_type": random.choice(agent_types),  # noqa: S311
                    "status": random.choice(  # noqa: S311
                        ["healthy", "healthy", "healthy", "degraded", "offline"]
                    ),  # noqa: S311
                    "utilization": round(random.uniform(0.1, 0.95), 2),  # noqa: S311
                    "last_heartbeat": now.isoformat(),
                }
            )

        assessment = FleetAssessment(
            assessment_id=f"fa-{uuid4().hex[:8]}",
            total_agents=total,
            healthy_count=healthy,
            degraded_count=degraded,
            offline_count=offline,
            fleet_status=status,
            capacity_utilization=utilization,
            available_capacity=round(1.0 - utilization, 2),
            agent_statuses=agent_statuses,
            assessed_at=now,
        )

        logger.info(
            "aoc_fleet_assessed",
            total=total,
            healthy=healthy,
            status=status.value,
            utilization=utilization,
        )
        return assessment

    # ---- Operation Planning ----

    async def plan_operations(
        self,
        assessment: FleetAssessment,
        config: dict[str, Any] | None = None,
    ) -> list[OperationPlan]:
        """Plan operations based on fleet assessment and config.

        Args:
            assessment: Current fleet assessment.
            config: Operation configuration.

        Returns:
            List of OperationPlan objects.
        """
        plans: list[OperationPlan] = []
        cfg = config or {}

        operation_types = cfg.get("operation_types", list(OperationType))
        if (
            isinstance(operation_types, list)
            and operation_types
            and isinstance(operation_types[0], str)
        ):
            operation_types = [OperationType(t) for t in operation_types]

        available_agents = [
            a
            for a in assessment.agent_statuses
            if a.get("status") == "healthy" and a.get("utilization", 1.0) < 0.8
        ]

        priorities = ["critical", "high", "medium", "low"]

        for _unused_i, op_type in enumerate(operation_types[:5]):
            target_count = min(
                random.randint(2, 5),  # noqa: S311
                len(available_agents),
            )
            targets = random.sample(  # noqa: S311
                [a["agent_id"] for a in available_agents],
                k=min(target_count, len(available_agents)),
            )

            plans.append(
                OperationPlan(
                    plan_id=f"plan-{uuid4().hex[:8]}",
                    operation_type=(
                        op_type if isinstance(op_type, OperationType) else OperationType(op_type)
                    ),
                    priority=random.choice(priorities[:3]),  # noqa: S311
                    target_agents=targets,
                    parameters={
                        "scope": cfg.get("scope", "full"),
                        "depth": cfg.get("depth", "standard"),
                    },
                    estimated_duration_ms=random.randint(30000, 300000),  # noqa: S311
                    dependencies=[],
                    description=(
                        f"Planned {op_type if isinstance(op_type, str) else op_type.value} "
                        f"operation across {len(targets)} agents"
                    ),
                )
            )

        logger.info(
            "aoc_operations_planned",
            plans=len(plans),
            available_agents=len(available_agents),
        )
        return plans

    # ---- Task Dispatch ----

    async def dispatch_tasks(
        self,
        plans: list[OperationPlan],
    ) -> list[TaskDispatch]:
        """Dispatch tasks to agents based on operation plans.

        Args:
            plans: Operation plans to dispatch.

        Returns:
            List of TaskDispatch objects.
        """
        dispatches: list[TaskDispatch] = []
        now = datetime.now(UTC)

        for plan in plans:
            for agent_id in plan.target_agents:
                dispatches.append(
                    TaskDispatch(
                        task_id=f"task-{uuid4().hex[:8]}",
                        plan_id=plan.plan_id,
                        agent_id=agent_id,
                        operation_type=plan.operation_type,
                        parameters=plan.parameters,
                        dispatched_at=now,
                        status="dispatched",
                        timeout_ms=plan.estimated_duration_ms * 2,
                    )
                )

        logger.info(
            "aoc_tasks_dispatched",
            plans=len(plans),
            tasks=len(dispatches),
        )
        return dispatches

    # ---- Execution Monitoring ----

    async def monitor_execution(
        self,
        tasks: list[TaskDispatch],
    ) -> list[ExecutionStatus]:
        """Monitor execution status of dispatched tasks.

        Args:
            tasks: Dispatched tasks to monitor.

        Returns:
            List of ExecutionStatus objects.
        """
        statuses: list[ExecutionStatus] = []
        now = datetime.now(UTC)

        status_options = [
            "completed",
            "completed",
            "completed",
            "completed",
            "failed",
            "timeout",
        ]

        for task in tasks:
            status = random.choice(status_options)  # noqa: S311
            duration = random.randint(5000, 120000)  # noqa: S311

            errors: list[str] = []
            if status == "failed":
                errors.append(f"Task {task.task_id} failed on agent {task.agent_id}")
            elif status == "timeout":
                errors.append(f"Task {task.task_id} timed out after {task.timeout_ms}ms")

            statuses.append(
                ExecutionStatus(
                    task_id=task.task_id,
                    agent_id=task.agent_id,
                    status=status,
                    progress_pct=100.0 if status == "completed" else 0.0,
                    started_at=task.dispatched_at,
                    completed_at=now,
                    duration_ms=duration,
                    result_summary=(f"{task.operation_type.value}: {status}"),
                    errors=errors,
                )
            )

        logger.info(
            "aoc_execution_monitored",
            tasks=len(tasks),
            completed=sum(1 for s in statuses if s.status == "completed"),
            failed=sum(1 for s in statuses if s.status in ("failed", "timeout")),
        )
        return statuses

    # ---- Outcome Evaluation ----

    async def evaluate_outcomes(
        self,
        statuses: list[ExecutionStatus],
        plans: list[OperationPlan],
    ) -> list[OutcomeEvaluation]:
        """Evaluate outcomes of completed operations.

        Args:
            statuses: Execution statuses.
            plans: Original operation plans.

        Returns:
            List of OutcomeEvaluation objects.
        """
        evaluations: list[OutcomeEvaluation] = []

        # Group statuses by plan
        by_plan: dict[str, list[ExecutionStatus]] = {}

        # Build task-to-plan mapping from plans and tasks
        for plan in plans:
            by_plan.setdefault(plan.plan_id, [])

        for status in statuses:
            # Find plan for this task
            for plan in plans:
                if any(agent_id in status.agent_id for agent_id in plan.target_agents):
                    by_plan.setdefault(plan.plan_id, []).append(status)
                    break
            else:
                # Assign to first plan as fallback
                if plans:
                    by_plan.setdefault(plans[0].plan_id, []).append(status)

        for plan_id, plan_statuses in by_plan.items():
            if not plan_statuses:
                continue

            total = len(plan_statuses)
            succeeded = sum(1 for s in plan_statuses if s.status == "completed")
            failed = total - succeeded
            avg_dur = sum(s.duration_ms for s in plan_statuses) // max(total, 1)
            rate = succeeded / max(total, 1)

            findings = []
            if rate >= 0.9:
                findings.append("Operation completed with high success rate")
            elif rate >= 0.7:
                findings.append("Most tasks completed successfully")
            else:
                findings.append("Significant task failures observed")

            if failed > 0:
                findings.append(f"{failed} tasks failed or timed out")

            suggestions = []
            if rate < 0.9:
                suggestions.append("Review failed task configurations")
                suggestions.append("Consider increasing task timeouts")
            if avg_dur > 60000:
                suggestions.append("Optimize long-running operations")

            evaluations.append(
                OutcomeEvaluation(
                    evaluation_id=f"eval-{uuid4().hex[:8]}",
                    plan_id=plan_id,
                    tasks_total=total,
                    tasks_succeeded=succeeded,
                    tasks_failed=failed,
                    success_rate=round(rate, 3),
                    avg_duration_ms=avg_dur,
                    key_findings=findings,
                    improvement_suggestions=suggestions,
                )
            )

        logger.info(
            "aoc_outcomes_evaluated",
            evaluations=len(evaluations),
            overall_success=round(
                sum(e.success_rate for e in evaluations) / max(len(evaluations), 1),
                3,
            ),
        )
        return evaluations

    # ---- Metrics ----

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record an autonomous ops controller metric."""
        self._metrics.append(
            {
                "name": metric_name,
                "value": value,
                "tags": tags or {},
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )
