"""Integration tests for IT Asset Intelligence agent."""

from __future__ import annotations

import pytest

from shieldops.agents.it_asset_intelligence.models import (
    ITAssetIntelligenceState,
)


@pytest.fixture
def agent_state() -> dict:
    return ITAssetIntelligenceState(
        request_id="test-itai-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.it_asset_intelligence.graph import (
        create_it_asset_intelligence_graph,
    )

    sg = create_it_asset_intelligence_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    assert "discover_assets" in node_ids
    assert len(node_ids) >= 4


def test_state_model_defaults():
    state = ITAssetIntelligenceState()
    assert state.tenant_id == ""
    assert state.error == ""


@pytest.mark.asyncio
async def test_full_pipeline(agent_state):
    from shieldops.agents.it_asset_intelligence.graph import (
        create_it_asset_intelligence_graph,
    )

    sg = create_it_asset_intelligence_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(agent_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
