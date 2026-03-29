"""Tests for shieldops.agents.asset_inventory."""

from __future__ import annotations

from shieldops.agents.asset_inventory.models import (
    AssetInventoryState,
    AssetType,
    Criticality,
    InventoryStage,
)


class TestEnums:
    def test_stage_discover(self):
        assert InventoryStage.DISCOVER == "discover"

    def test_stage_classify(self):
        assert InventoryStage.CLASSIFY == "classify"

    def test_stage_assign_owners(self):
        assert InventoryStage.ASSIGN_OWNERS == "assign_owners"

    def test_stage_assess_risk(self):
        assert InventoryStage.ASSESS_RISK == "assess_risk"

    def test_stage_reconcile(self):
        assert InventoryStage.RECONCILE == "reconcile"

    def test_stage_report(self):
        assert InventoryStage.REPORT == "report"

    def test_asset_type_server(self):
        assert AssetType.SERVER == "server"

    def test_asset_type_container(self):
        assert AssetType.CONTAINER == "container"

    def test_asset_type_database(self):
        assert AssetType.DATABASE == "database"

    def test_asset_type_api_endpoint(self):
        assert AssetType.API_ENDPOINT == "api_endpoint"

    def test_asset_type_ai_model(self):
        assert AssetType.AI_MODEL == "ai_model"

    def test_asset_type_unknown(self):
        assert AssetType.UNKNOWN == "unknown"

    def test_criticality_critical(self):
        assert Criticality.CRITICAL == "critical"

    def test_criticality_high(self):
        assert Criticality.HIGH == "high"

    def test_criticality_medium(self):
        assert Criticality.MEDIUM == "medium"

    def test_criticality_low(self):
        assert Criticality.LOW == "low"

    def test_criticality_informational(self):
        assert Criticality.INFORMATIONAL == "informational"


class TestModels:
    def test_state_defaults(self):
        s = AssetInventoryState(tenant_id="t-01")
        assert s.error == ""

    def test_state_stage_default(self):
        s = AssetInventoryState()
        assert s.stage == InventoryStage.DISCOVER

    def test_state_empty_lists(self):
        s = AssetInventoryState()
        assert s.discovered_assets == []
        assert s.classifications == []
        assert s.owner_assignments == []
        assert s.risk_assessments == []

    def test_state_counters_default(self):
        s = AssetInventoryState()
        assert s.total_assets == 0
        assert s.unmanaged_count == 0
        assert s.critical_count == 0


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.asset_inventory.graph import (
            create_asset_inventory_graph,
        )

        sg = create_asset_inventory_graph()
        assert sg.compile() is not None
