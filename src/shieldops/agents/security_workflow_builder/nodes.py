"""Security Workflow Builder Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    ReasoningStep,
    SWBStage,
    TriggerDefinition,
    ValidationResult,
    WorkflowDefinition,
)
from .tools import SecurityWorkflowBuilderToolkit

logger = structlog.get_logger()

_toolkit: SecurityWorkflowBuilderToolkit | None = None  # noqa: PLW0603


def _get_toolkit() -> SecurityWorkflowBuilderToolkit:
    if _toolkit is None:
        msg = "Toolkit not initialised — toolkit required"
        raise RuntimeError(msg)
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Define Trigger
# ------------------------------------------------------------------


async def define_trigger(
    state: dict[str, Any],
    toolkit: SecurityWorkflowBuilderToolkit,
) -> dict[str, Any]:
    """Define workflow trigger conditions."""
    logger.info("swb.node.define_trigger")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    triggers = await toolkit.define_trigger(tenant_id)
    data = [t.model_dump() for t in triggers]

    note = f"Defined {len(triggers)} workflow triggers"

    return {
        "stage": SWBStage.BUILD_WORKFLOW.value,
        "triggers": data,
        "current_step": "define_trigger",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="define_trigger",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Build Workflow
# ------------------------------------------------------------------


async def build_workflow(
    state: dict[str, Any],
    toolkit: SecurityWorkflowBuilderToolkit,
) -> dict[str, Any]:
    """Build workflow definitions from triggers."""
    logger.info("swb.node.build_workflow")
    state = _to_dict(state)

    triggers = [TriggerDefinition(**t) for t in state.get("triggers", [])]
    workflows = await toolkit.build_workflow(triggers)
    data = [w.model_dump() for w in workflows]

    total_steps = sum(len(w.steps) for w in workflows)
    note = f"Built {len(workflows)} workflows with {total_steps} total steps"

    try:
        from .prompts import SYSTEM_ANALYZE, WorkflowInsight

        ctx = json.dumps(
            {
                "workflows": [
                    {
                        "name": w.name,
                        "steps": len(w.steps),
                        "trigger": w.trigger_id,
                    }
                    for w in workflows[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            WorkflowInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Workflow designs:\n{ctx}",
                schema=WorkflowInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="swb",
            node="build_workflow",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="swb",
            node="build_workflow",
        )

    return {
        "stage": SWBStage.VALIDATE_LOGIC.value,
        "workflows": data,
        "workflows_built": len(workflows),
        "current_step": "build_workflow",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="build_workflow",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Validate Logic
# ------------------------------------------------------------------


async def validate_logic(
    state: dict[str, Any],
    toolkit: SecurityWorkflowBuilderToolkit,
) -> dict[str, Any]:
    """Validate workflow logic and dependencies."""
    logger.info("swb.node.validate_logic")
    state = _to_dict(state)

    workflows = [WorkflowDefinition(**w) for w in state.get("workflows", [])]
    validations = await toolkit.validate_logic(workflows)
    data = [v.model_dump() for v in validations]

    valid_count = sum(1 for v in validations if v.valid)
    note = f"Validated {len(validations)} workflows, {valid_count} passed"

    return {
        "stage": SWBStage.TEST_EXECUTION.value,
        "validations": data,
        "current_step": "validate_logic",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="validate_logic",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Test Execution
# ------------------------------------------------------------------


async def test_execution(
    state: dict[str, Any],
    toolkit: SecurityWorkflowBuilderToolkit,
) -> dict[str, Any]:
    """Execute workflows in sandbox for testing."""
    logger.info("swb.node.test_execution")
    state = _to_dict(state)

    workflows = [WorkflowDefinition(**w) for w in state.get("workflows", [])]
    test_results = await toolkit.test_execution(workflows)
    data = [t.model_dump() for t in test_results]

    passed = sum(1 for t in test_results if t.status == "passed")
    note = f"Tested {len(test_results)} workflows, {passed} passed"

    return {
        "stage": SWBStage.DEPLOY.value,
        "test_results": data,
        "tests_passed": passed,
        "current_step": "test_execution",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="test_execution",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Deploy
# ------------------------------------------------------------------


async def deploy_workflow(
    state: dict[str, Any],
    toolkit: SecurityWorkflowBuilderToolkit,
) -> dict[str, Any]:
    """Deploy validated workflows."""
    logger.info("swb.node.deploy_workflow")
    state = _to_dict(state)

    workflows = [WorkflowDefinition(**w) for w in state.get("workflows", [])]
    validations = [ValidationResult(**v) for v in state.get("validations", [])]
    deployments = await toolkit.deploy_workflow(workflows, validations)
    data = [d.model_dump() for d in deployments]

    deployed = sum(1 for d in deployments if d.status == "deployed")
    note = f"Deployed {deployed}/{len(deployments)} workflows"

    return {
        "stage": SWBStage.REPORT.value,
        "deployments": data,
        "current_step": "deploy_workflow",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="deploy_workflow",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: SecurityWorkflowBuilderToolkit,
) -> dict[str, Any]:
    """Compile the final workflow builder report."""
    logger.info("swb.node.report")
    state = _to_dict(state)

    wf_count = state.get("workflows_built", 0)
    tests = state.get("tests_passed", 0)
    deploy_count = len(state.get("deployments", []))
    valid_count = len(state.get("validations", []))

    lines = [
        "# Security Workflow Builder Report",
        "",
        f"**Workflows built:** {wf_count}",
        f"**Validations run:** {valid_count}",
        f"**Tests passed:** {tests}",
        f"**Deployments:** {deploy_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "workflows": wf_count,
                "validations": valid_count,
                "tests_passed": tests,
                "deployments": deploy_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Workflow builder report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="swb",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="swb",
            node="report",
        )

    return {
        "stage": SWBStage.REPORT.value,
        "report": report_text,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
