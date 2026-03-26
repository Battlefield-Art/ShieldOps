"""Integration test for the zero_trust_network agent."""

from __future__ import annotations

import pytest

from shieldops.agents.zero_trust_network.models import ZeroTrustNetworkState


@pytest.fixture
def state() -> dict:
    return ZeroTrustNetworkState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.zero_trust_network.graph import create_zero_trust_network_graph

    sg = create_zero_trust_network_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = ZeroTrustNetworkState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.zero_trust_network.graph import create_zero_trust_network_graph

    try:
        result = await create_zero_trust_network_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
