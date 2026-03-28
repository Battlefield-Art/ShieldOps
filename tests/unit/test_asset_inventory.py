"""Unit tests for asset_inventory agent."""

from __future__ import annotations

from shieldops.agents.asset_inventory.models import (
    AssetInventoryState,
    AssetType,
    ClassifiedAsset,
    Criticality,
    DiscoveredAsset,
    InventoryStage,
)
from shieldops.agents.asset_inventory.tools import AssetInventoryToolkit


class TestEnums:
    def test_assettype_values(self) -> None:
        assert AssetType.SERVER == "server"
        assert len(AssetType) >= 3

    def test_criticality_values(self) -> None:
        assert Criticality.CRITICAL == "critical"
        assert len(Criticality) >= 3

    def test_inventorystage_values(self) -> None:
        assert InventoryStage.DISCOVER == "discover"
        assert len(InventoryStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        state = AssetInventoryState()
        assert state.request_id == ""
        assert state.error == ""

    def test_with_values(self) -> None:
        state = AssetInventoryState(request_id="t-1", tenant_id="t-1")
        assert state.request_id == "t-1"


class TestClassifiedAsset:
    def test_defaults(self) -> None:
        obj = ClassifiedAsset()
        assert obj is not None


class TestDiscoveredAsset:
    def test_defaults(self) -> None:
        obj = DiscoveredAsset()
        assert obj is not None


class TestToolkit:
    def test_init(self) -> None:
        toolkit = AssetInventoryToolkit()
        assert toolkit is not None
