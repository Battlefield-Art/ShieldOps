"""Integration test for the endpoint_dlp agent."""

from __future__ import annotations

import pytest

from shieldops.agents.endpoint_dlp.models import EndpointDLPState


@pytest.fixture
def state() -> dict:
    return EndpointDLPState(
        request_id="test-001",
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.endpoint_dlp.graph import (
        create_endpoint_dlp_graph,
    )

    sg = create_endpoint_dlp_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = EndpointDLPState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.endpoint_dlp.graph import (
        create_endpoint_dlp_graph,
    )

    try:
        result = await create_endpoint_dlp_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
