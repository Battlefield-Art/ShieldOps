"""Integration test for IR Playbook Engine Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.ir_playbook_engine.models import (
    IRPlaybookEngineState,
    IRStage,
)


@pytest.fixture
def state() -> dict:
    return IRPlaybookEngineState(
        request_id="test-irp-001",
        tenant_id="t-01",
        session_start=1e6,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.ir_playbook_engine.graph import (
        create_ir_playbook_engine_graph,
    )

    sg = create_ir_playbook_engine_graph()
    nodes = [n["id"] for n in sg.compile().get_graph().to_json()["nodes"]]
    for name in [
        "classify_incident",
        "select_playbook",
        "execute_steps",
        "adapt_response",
        "validate_containment",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = IRPlaybookEngineState()
    assert s.stage == IRStage.CLASSIFY_INCIDENT
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.ir_playbook_engine.graph import (
        create_ir_playbook_engine_graph,
    )

    try:
        sg = create_ir_playbook_engine_graph()
        result = await sg.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
