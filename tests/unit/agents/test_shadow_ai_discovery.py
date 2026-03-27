"""Tests for shieldops.agents.shadow_ai_discovery."""

from __future__ import annotations

from shieldops.agents.shadow_ai_discovery.models import (
    AIAssetType,
    DiscoveryStage,
    GovernanceStatus,
    ShadowAIDiscoveryState,
)


class TestEnums:
    def test_discoverystage_scan_network(self):
        assert DiscoveryStage.SCAN_NETWORK == "scan_network"

    def test_discoverystage_analyze_traffic(self):
        assert DiscoveryStage.ANALYZE_TRAFFIC == "analyze_traffic"

    def test_discoverystage_identify_agents(self):
        assert DiscoveryStage.IDENTIFY_AGENTS == "identify_agents"

    def test_discoverystage_classify_risk(self):
        assert DiscoveryStage.CLASSIFY_RISK == "classify_risk"

    def test_aiassettype_llm_api_client(self):
        assert AIAssetType.LLM_API_CLIENT == "llm_api_client"

    def test_aiassettype_mcp_server(self):
        assert AIAssetType.MCP_SERVER == "mcp_server"

    def test_aiassettype_rag_pipeline(self):
        assert AIAssetType.RAG_PIPELINE == "rag_pipeline"

    def test_aiassettype_fine_tuned_model(self):
        assert AIAssetType.FINE_TUNED_MODEL == "fine_tuned_model"

    def test_governancestatus_managed(self):
        assert GovernanceStatus.MANAGED == "managed"

    def test_governancestatus_unmanaged(self):
        assert GovernanceStatus.UNMANAGED == "unmanaged"

    def test_governancestatus_shadow(self):
        assert GovernanceStatus.SHADOW == "shadow"

    def test_governancestatus_rogue(self):
        assert GovernanceStatus.ROGUE == "rogue"


class TestModels:
    def test_state_defaults(self):
        s = ShadowAIDiscoveryState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.shadow_ai_discovery.graph import (
            create_shadow_ai_discovery_graph,
        )

        sg = create_shadow_ai_discovery_graph()
        assert sg.compile() is not None
