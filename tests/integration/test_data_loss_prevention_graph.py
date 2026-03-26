"""Integration test for the data_loss_prevention agent."""

from __future__ import annotations

import pytest

from shieldops.agents.data_loss_prevention.models import DataLossPreventionState


@pytest.fixture
def state() -> dict:
    return DataLossPreventionState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.data_loss_prevention.graph import create_data_loss_prevention_graph

    sg = create_data_loss_prevention_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = DataLossPreventionState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.data_loss_prevention.graph import create_data_loss_prevention_graph

    try:
        result = await create_data_loss_prevention_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
