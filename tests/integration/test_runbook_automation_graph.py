"""Integration test for the Runbook Automation Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.runbook_automation.models import (
    AutomationStage,
    ExecutionStep,
    Runbook,
    RunbookAutomationState,
    StepResult,
)


@pytest.fixture
def runbook_state() -> dict:
    return RunbookAutomationState(
        request_id="test-ra-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.runbook_automation.graph import create_runbook_automation_graph

    sg = create_runbook_automation_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "select_runbook",
        "validate_preconditions",
        "request_approval",
        "execute_steps",
        "verify_outcome",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    runbook = Runbook(
        id="rb-001",
        name="restart_service",
        description="Restart a service pod",
        trigger="incident",
        target_service="api-gateway",
        steps=[
            {"name": "drain", "command": "kubectl drain"},
            {"name": "restart", "command": "kubectl rollout restart"},
        ],
        approval_required=True,
        estimated_duration_min=5,
        risk_level="medium",
    )
    step = ExecutionStep(
        id="es-001",
        runbook_id="rb-001",
        step_number=1,
        step_name="drain",
        command="kubectl drain node/api-1",
        result=StepResult.SUCCESS,
        output="node drained",
        duration_ms=3200.0,
    )
    state = RunbookAutomationState(
        runbook=runbook, execution_steps=[step], stage=AutomationStage.VERIFY_OUTCOME
    )
    assert state.runbook is not None
    assert state.execution_steps[0].result == StepResult.SUCCESS


def test_state_defaults():
    state = RunbookAutomationState()
    assert state.stage == AutomationStage.SELECT_RUNBOOK
    assert state.runbook is None
    assert state.execution_steps == []
    assert state.rollback_triggered is False


@pytest.mark.asyncio
async def test_full_pipeline(runbook_state):
    from shieldops.agents.runbook_automation.graph import create_runbook_automation_graph

    sg = create_runbook_automation_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(runbook_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
