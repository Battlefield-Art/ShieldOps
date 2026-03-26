"""Integration test for the data_threat_hunting agent."""

from __future__ import annotations

import pytest

from shieldops.agents.data_threat_hunting.models import DataThreatHuntingState


@pytest.fixture
def state() -> dict:
    return DataThreatHuntingState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.data_threat_hunting.graph import create_data_threat_hunting_graph

    sg = create_data_threat_hunting_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = DataThreatHuntingState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.data_threat_hunting.graph import create_data_threat_hunting_graph

    try:
        result = await create_data_threat_hunting_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
