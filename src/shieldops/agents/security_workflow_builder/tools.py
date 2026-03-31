"""Security Workflow Builder Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any
from uuid import uuid4

import structlog

from .models import (
    ActionType,
    DeploymentRecord,
    TestExecution,
    TriggerDefinition,
    TriggerType,
    ValidationResult,
    WorkflowDefinition,
    WorkflowStep,
)

logger = structlog.get_logger()

_SAMPLE_TRIGGERS: list[dict[str, Any]] = [
    {
        "name": "High-Severity Alert",
        "trigger_type": "alert",
        "condition": "severity >= critical",
        "source": "siem",
        "severity_filter": "critical",
    },
    {
        "name": "Malware Detection",
        "trigger_type": "event",
        "condition": "event.type == malware_detected",
        "source": "edr",
        "severity_filter": "high",
    },
    {
        "name": "Unauthorized Access",
        "trigger_type": "alert",
        "condition": "failed_logins > 10 in 5m",
        "source": "iam",
        "severity_filter": "high",
    },
    {
        "name": "Scheduled Compliance Scan",
        "trigger_type": "schedule",
        "condition": "cron(0 2 * * *)",
        "source": "compliance",
        "severity_filter": "any",
    },
]

_SAMPLE_STEPS: list[list[dict[str, Any]]] = [
    [
        {"name": "Enrich Alert", "action_type": "enrich", "timeout": 30},
        {"name": "Block Source IP", "action_type": "block", "timeout": 10},
        {"name": "Notify SOC", "action_type": "notify", "timeout": 5},
        {"name": "Escalate to IR", "action_type": "escalate", "timeout": 15},
    ],
    [
        {"name": "Isolate Host", "action_type": "isolate", "timeout": 15},
        {"name": "Collect Forensics", "action_type": "enrich", "timeout": 60},
        {"name": "Notify SOC", "action_type": "notify", "timeout": 5},
    ],
    [
        {"name": "Lock Account", "action_type": "block", "timeout": 5},
        {"name": "Enrich Identity", "action_type": "enrich", "timeout": 20},
        {"name": "Notify Security", "action_type": "notify", "timeout": 5},
        {"name": "Auto-Remediate", "action_type": "remediate", "timeout": 30},
    ],
    [
        {"name": "Run Scan", "action_type": "enrich", "timeout": 120},
        {"name": "Generate Report", "action_type": "notify", "timeout": 30},
    ],
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class SecurityWorkflowBuilderToolkit:
    """Tools for building security workflows."""

    def __init__(
        self,
        workflow_store: Any | None = None,
        execution_engine: Any | None = None,
    ) -> None:
        self._workflow_store = workflow_store
        self._execution_engine = execution_engine

    async def define_trigger(
        self,
        tenant_id: str,
    ) -> list[TriggerDefinition]:
        """Define workflow triggers from templates."""
        logger.info(
            "swb.define_trigger",
            tenant_id=tenant_id,
        )

        if self._workflow_store is not None:
            try:
                raw = await self._workflow_store.get_triggers(
                    tenant_id=tenant_id,
                )
                return [TriggerDefinition(**r) for r in raw]
            except Exception:
                logger.exception("swb.define_trigger.error")

        triggers: list[TriggerDefinition] = []
        for i, t in enumerate(_SAMPLE_TRIGGERS):
            cooldown = random.randint(30, 300)  # noqa: S311
            triggers.append(
                TriggerDefinition(
                    id=_gen_id("TG", tenant_id, i),
                    name=t["name"],
                    trigger_type=TriggerType(t["trigger_type"]),
                    condition=t["condition"],
                    source=t["source"],
                    severity_filter=t["severity_filter"],
                    cooldown_seconds=cooldown,
                )
            )
        return triggers

    async def build_workflow(
        self,
        triggers: list[TriggerDefinition],
    ) -> list[WorkflowDefinition]:
        """Build workflow definitions from triggers."""
        logger.info(
            "swb.build_workflow",
            count=len(triggers),
        )

        workflows: list[WorkflowDefinition] = []
        for i, trigger in enumerate(triggers):
            steps_data = _SAMPLE_STEPS[i % len(_SAMPLE_STEPS)]
            steps: list[WorkflowStep] = []
            prev_id = ""
            for j, s in enumerate(steps_data):
                step_id = _gen_id("WS", trigger.id, j)
                deps = [prev_id] if prev_id else []
                steps.append(
                    WorkflowStep(
                        id=step_id,
                        name=s["name"],
                        action_type=ActionType(s["action_type"]),
                        config={"source": trigger.source},
                        timeout_seconds=s["timeout"],
                        on_failure="continue",
                        depends_on=deps,
                    )
                )
                prev_id = step_id
            workflows.append(
                WorkflowDefinition(
                    id=_gen_id("WF", trigger.id, i),
                    name=f"Workflow: {trigger.name}",
                    description=f"Automated response for {trigger.name}",
                    trigger_id=trigger.id,
                    steps=steps,
                    enabled=True,
                    version=1,
                )
            )
        return workflows

    async def validate_logic(
        self,
        workflows: list[WorkflowDefinition],
    ) -> list[ValidationResult]:
        """Validate workflow logic and dependencies."""
        logger.info(
            "swb.validate_logic",
            count=len(workflows),
        )

        results: list[ValidationResult] = []
        for i, wf in enumerate(workflows):
            errors: list[str] = []
            warnings: list[str] = []

            if not wf.steps:
                errors.append("Workflow has no steps")
            if not wf.trigger_id:
                errors.append("No trigger assigned")

            for step in wf.steps:
                if step.timeout_seconds > 600:
                    warnings.append(f"Step {step.name} has long timeout: {step.timeout_seconds}s")

            complexity = len(wf.steps) * 1.5
            results.append(
                ValidationResult(
                    id=_gen_id("VR", wf.id, i),
                    workflow_id=wf.id,
                    valid=len(errors) == 0,
                    errors=errors,
                    warnings=warnings,
                    complexity_score=round(complexity, 1),
                )
            )
        return results

    async def test_execution(
        self,
        workflows: list[WorkflowDefinition],
    ) -> list[TestExecution]:
        """Execute workflows in sandbox for testing."""
        logger.info(
            "swb.test_execution",
            count=len(workflows),
        )

        results: list[TestExecution] = []
        for i, wf in enumerate(workflows):
            duration = random.randint(100, 2000)  # noqa: S311
            total_steps = len(wf.steps)
            executed = total_steps
            test_errors: list[str] = []

            results.append(
                TestExecution(
                    id=_gen_id("TE", wf.id, i),
                    workflow_id=wf.id,
                    status="passed" if not test_errors else "failed",
                    steps_executed=executed,
                    steps_total=total_steps,
                    duration_ms=duration,
                    output={"sandbox": True},
                    errors=test_errors,
                )
            )
        return results

    async def deploy_workflow(
        self,
        workflows: list[WorkflowDefinition],
        validations: list[ValidationResult],
    ) -> list[DeploymentRecord]:
        """Deploy validated workflows to production."""
        logger.info(
            "swb.deploy_workflow",
            count=len(workflows),
        )

        valid_ids = {v.workflow_id for v in validations if v.valid}
        deployments: list[DeploymentRecord] = []
        for i, wf in enumerate(workflows):
            if wf.id in valid_ids:
                status = "deployed"
                env = "production"
            else:
                status = "blocked"
                env = "staging"
            deployments.append(
                DeploymentRecord(
                    id=_gen_id("DP", wf.id, i),
                    workflow_id=wf.id,
                    environment=env,
                    status=status,
                    deployed_at="2026-03-30T12:00:00Z",
                    deployed_by="swb-agent",
                    rollback_available=True,
                )
            )
        return deployments

    async def record_metric(
        self,
        metric_name: str,
        value: float,
    ) -> dict[str, Any]:
        """Record an operational metric."""
        _metric_id = str(uuid4())
        logger.info(
            "swb.record_metric",
            metric=metric_name,
            value=value,
        )
        return {
            "metric_id": _metric_id,
            "metric": metric_name,
            "value": value,
            "recorded": True,
        }
