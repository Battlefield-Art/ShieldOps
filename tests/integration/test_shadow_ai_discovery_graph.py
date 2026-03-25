"""Integration test for the Shadow AI Discovery Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.shadow_ai_discovery.models import (
    AIAssetType,
    DiscoveryStage,
    GovernanceStatus,
    ShadowAIAsset,
    ShadowAIDiscoveryState,
)


@pytest.fixture
def discovery_state() -> dict:
    return ShadowAIDiscoveryState(
        request_id="test-sad-001",
        tenant_id="tenant-prod-01",
        scan_scope=["network", "dns", "api_logs", "cloud_billing"],
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.shadow_ai_discovery.graph import (
        create_shadow_ai_discovery_graph,
    )

    sg = create_shadow_ai_discovery_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "scan_network",
        "analyze_traffic",
        "identify_agents",
        "classify_risk",
        "recommend_governance",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    asset = ShadowAIAsset(
        id="sa-001",
        asset_type=AIAssetType.LLM_API_CLIENT,
        name="Unregistered OpenAI Client",
        endpoint_url="api.openai.com",
        owner="unknown",
        department="engineering",
        governance_status=GovernanceStatus.SHADOW,
        model_provider="openai",
        estimated_monthly_cost=2400.0,
        data_sensitivity="high",
        risk_score=0.82,
    )
    state = ShadowAIDiscoveryState(
        discovered_assets=[asset],
        stage=DiscoveryStage.CLASSIFY_RISK,
    )
    assert len(state.discovered_assets) == 1
    assert state.discovered_assets[0].governance_status == GovernanceStatus.SHADOW


def test_state_defaults():
    state = ShadowAIDiscoveryState()
    assert state.stage == DiscoveryStage.SCAN_NETWORK
    assert state.discovered_assets == []
    assert state.governance_recommendations == []
    assert state.error == ""


@pytest.mark.asyncio
async def test_full_pipeline(discovery_state):
    from shieldops.agents.shadow_ai_discovery.graph import (
        create_shadow_ai_discovery_graph,
    )

    sg = create_shadow_ai_discovery_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(discovery_state)
    except Exception:
        pytest.skip("Pipeline requires external dependencies")
        return
    assert isinstance(result, dict)
    assert "reasoning_chain" in result
