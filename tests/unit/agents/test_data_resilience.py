"""Tests for shieldops.agents.data_resilience."""

from __future__ import annotations

from shieldops.agents.data_resilience.models import (
    DataAssetType,
    DataResilienceState,
    ProtectionLevel,
    ResilienceStage,
)


class TestEnums:
    def test_resiliencestage_inventory_data_assets(self):
        assert ResilienceStage.INVENTORY_DATA_ASSETS == "inventory_data_assets"

    def test_resiliencestage_assess_protection(self):
        assert ResilienceStage.ASSESS_PROTECTION == "assess_protection"

    def test_resiliencestage_detect_anomalies(self):
        assert ResilienceStage.DETECT_ANOMALIES == "detect_anomalies"

    def test_resiliencestage_enforce_immutability(self):
        assert ResilienceStage.ENFORCE_IMMUTABILITY == "enforce_immutability"

    def test_protectionlevel_immutable(self):
        assert ProtectionLevel.IMMUTABLE == "immutable"

    def test_protectionlevel_versioned(self):
        assert ProtectionLevel.VERSIONED == "versioned"

    def test_protectionlevel_replicated(self):
        assert ProtectionLevel.REPLICATED == "replicated"

    def test_protectionlevel_unprotected(self):
        assert ProtectionLevel.UNPROTECTED == "unprotected"

    def test_dataassettype_database(self):
        assert DataAssetType.DATABASE == "database"

    def test_dataassettype_object_storage(self):
        assert DataAssetType.OBJECT_STORAGE == "object_storage"

    def test_dataassettype_file_system(self):
        assert DataAssetType.FILE_SYSTEM == "file_system"

    def test_dataassettype_ai_model(self):
        assert DataAssetType.AI_MODEL == "ai_model"


class TestModels:
    def test_state_defaults(self):
        s = DataResilienceState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.data_resilience.graph import (
            create_data_resilience_graph,
        )

        sg = create_data_resilience_graph()
        assert sg.compile() is not None
