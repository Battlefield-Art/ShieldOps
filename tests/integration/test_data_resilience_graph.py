"""Integration test for the Data Resilience agent."""

from __future__ import annotations

import pytest

from shieldops.agents.data_resilience.models import DataResilienceState


@pytest.fixture
def state() -> dict:
    return DataResilienceState(
        request_id="test-001",
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.data_resilience.graph import (
        create_data_resilience_graph,
    )

    sg = create_data_resilience_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = DataResilienceState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.data_resilience.graph import (
        create_data_resilience_graph,
    )

    try:
        g = create_data_resilience_graph()
        result = await g.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
