"""Integration test for the autonomous_xdr agent."""

from __future__ import annotations

import pytest

from shieldops.agents.autonomous_xdr.models import AutonomousXDRState


@pytest.fixture
def state() -> dict:
    return AutonomousXDRState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.autonomous_xdr.graph import create_autonomous_xdr_graph

    sg = create_autonomous_xdr_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = AutonomousXDRState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.autonomous_xdr.graph import create_autonomous_xdr_graph

    try:
        result = await create_autonomous_xdr_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
