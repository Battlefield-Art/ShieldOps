"""Tests for shieldops.agents.it_asset_intelligence."""

from __future__ import annotations

from shieldops.agents.it_asset_intelligence.models import (
    AssetCategory,
    AssetStage,
    ITAssetIntelligenceState,
    RiskPosture,
)


class TestEnums:
    def test_assetstage_discover_assets(self):
        assert AssetStage.DISCOVER_ASSETS == "discover_assets"

    def test_assetstage_classify_criticality(self):
        assert AssetStage.CLASSIFY_CRITICALITY == "classify_criticality"

    def test_assetstage_assess_security_posture(self):
        assert AssetStage.ASSESS_SECURITY_POSTURE == "assess_security_posture"

    def test_assetstage_correlate_with_threats(self):
        assert AssetStage.CORRELATE_WITH_THREATS == "correlate_with_threats"

    def test_assetcategory_server(self):
        assert AssetCategory.SERVER == "server"

    def test_assetcategory_endpoint(self):
        assert AssetCategory.ENDPOINT == "endpoint"

    def test_assetcategory_network_device(self):
        assert AssetCategory.NETWORK_DEVICE == "network_device"

    def test_assetcategory_cloud_resource(self):
        assert AssetCategory.CLOUD_RESOURCE == "cloud_resource"

    def test_riskposture_critical(self):
        assert RiskPosture.CRITICAL == "critical"

    def test_riskposture_high(self):
        assert RiskPosture.HIGH == "high"

    def test_riskposture_medium(self):
        assert RiskPosture.MEDIUM == "medium"

    def test_riskposture_low(self):
        assert RiskPosture.LOW == "low"


class TestModels:
    def test_state_defaults(self):
        s = ITAssetIntelligenceState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.it_asset_intelligence.graph import (
            create_it_asset_intelligence_graph,
        )

        sg = create_it_asset_intelligence_graph()
        assert sg.compile() is not None
