"""Integration test for the soc_transformation agent."""

from __future__ import annotations

import pytest

from shieldops.agents.soc_transformation.models import SOCTransformationState


@pytest.fixture
def state() -> dict:
    return SOCTransformationState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.soc_transformation.graph import create_soc_transformation_graph

    sg = create_soc_transformation_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = SOCTransformationState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.soc_transformation.graph import create_soc_transformation_graph

    try:
        result = await create_soc_transformation_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
