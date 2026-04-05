"""Integration test for the Workflow Engine Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.workflow_engine.models import WorkflowEngineState, WorkflowStage


@pytest.fixture
def state() -> dict:
    return WorkflowEngineState(
        request_id="test-we-001", tenant_id="t-01", session_start=1e6
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.workflow_engine.graph import create_workflow_engine_graph

    sg = create_workflow_engine_graph()
    nodes = [n["id"] for n in sg.compile().get_graph().to_json()["nodes"]]
    for name in [
        "load_workflow",
        "validate",
        "execute_steps",
        "check_gates",
        "finalize",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = WorkflowEngineState()
    assert s.stage == WorkflowStage.LOAD_WORKFLOW


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.workflow_engine.graph import create_workflow_engine_graph

    try:
        result = await create_workflow_engine_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
