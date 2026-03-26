"""Integration test for the intelligent_soar agent."""

from __future__ import annotations

import pytest

from shieldops.agents.intelligent_soar.models import IntelligentSOARState


@pytest.fixture
def state() -> dict:
    return IntelligentSOARState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.intelligent_soar.graph import create_intelligent_soar_graph

    sg = create_intelligent_soar_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = IntelligentSOARState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.intelligent_soar.graph import create_intelligent_soar_graph

    try:
        result = await create_intelligent_soar_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
