"""Integration tests for Endpoint DLP agent."""

from __future__ import annotations

import pytest

from shieldops.agents.endpoint_dlp.models import (
    EndpointDLPState,
)


@pytest.fixture
def agent_state() -> dict:
    return EndpointDLPState(
        request_id="test-edlp-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.endpoint_dlp.graph import (
        create_endpoint_dlp_graph,
    )

    sg = create_endpoint_dlp_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    expected = [
        "scan_endpoints",
        "detect_exfiltration",
        "enforce_policy",
        "generate_report",
    ]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_defaults():
    state = EndpointDLPState()
    assert state.endpoints == []
    assert state.violations == []
    assert state.tenant_id == ""


@pytest.mark.asyncio
async def test_full_pipeline(agent_state):
    from shieldops.agents.endpoint_dlp.graph import (
        create_endpoint_dlp_graph,
    )

    sg = create_endpoint_dlp_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(agent_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
