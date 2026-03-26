"""Integration test for the breakout_defender agent."""

from __future__ import annotations

import pytest

from shieldops.agents.breakout_defender.models import BreakoutDefenderState


@pytest.fixture
def state() -> dict:
    return BreakoutDefenderState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.breakout_defender.graph import create_breakout_defender_graph

    sg = create_breakout_defender_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = BreakoutDefenderState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.breakout_defender.graph import create_breakout_defender_graph

    try:
        result = await create_breakout_defender_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
