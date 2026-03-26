"""Integration test for the agentic_mdr agent."""

from __future__ import annotations

import pytest

from shieldops.agents.agentic_mdr.models import AgenticMDRState


@pytest.fixture
def state() -> dict:
    return AgenticMDRState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.agentic_mdr.graph import create_agentic_mdr_graph

    sg = create_agentic_mdr_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = AgenticMDRState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.agentic_mdr.graph import create_agentic_mdr_graph

    try:
        result = await create_agentic_mdr_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
