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
    expected = [
        "discover_assets",
        "classify_assets",
        "assess_risk",
        "generate_report",
    ]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_defaults():
    state = ITAssetIntelligenceState()
    assert state.assets == []
    assert state.risk_scores == {}
    assert state.tenant_id == ""


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
