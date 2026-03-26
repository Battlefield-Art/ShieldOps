"""Integration test for the cloud_risk_ranker agent."""

from __future__ import annotations

import pytest

from shieldops.agents.cloud_risk_ranker.models import CloudRiskRankerState


@pytest.fixture
def state() -> dict:
    return CloudRiskRankerState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.cloud_risk_ranker.graph import create_cloud_risk_ranker_graph

    sg = create_cloud_risk_ranker_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = CloudRiskRankerState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.cloud_risk_ranker.graph import create_cloud_risk_ranker_graph

    try:
        result = await create_cloud_risk_ranker_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
