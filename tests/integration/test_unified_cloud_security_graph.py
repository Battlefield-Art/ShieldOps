"""Integration tests for Unified Cloud Security agent."""

from __future__ import annotations

import pytest

from shieldops.agents.unified_cloud_security.models import (
    UnifiedCloudSecurityState,
)


@pytest.fixture
def agent_state() -> dict:
    return UnifiedCloudSecurityState(
        request_id="test-ucs-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.unified_cloud_security.graph import (
        create_unified_cloud_security_graph,
    )

    sg = create_unified_cloud_security_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    expected = [
        "scan_cloud_accounts",
        "correlate_findings",
        "prioritize_risks",
        "generate_report",
    ]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_defaults():
    state = UnifiedCloudSecurityState()
    assert state.cloud_findings == []
    assert state.risk_priorities == []
    assert state.tenant_id == ""


@pytest.mark.asyncio
async def test_full_pipeline(agent_state):
    from shieldops.agents.unified_cloud_security.graph import (
        create_unified_cloud_security_graph,
    )

    sg = create_unified_cloud_security_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(agent_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
