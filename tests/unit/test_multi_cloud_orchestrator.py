"""Tests for multi_cloud_orchestrator."""

from __future__ import annotations

from shieldops.agents.multi_cloud_orchestrator.models import (
    CloudProvider,
    MCOStage,
    MultiCloudOrchestratorState,
    PlacementStrategy,
)


class TestEnums:
    def test_stage(self) -> None:
        assert MCOStage.DISCOVER_RESOURCES == "discover_resources"
        assert len(MCOStage) >= 3

    def test_cloud_provider(self) -> None:
        assert CloudProvider.AWS == "aws"
        assert len(CloudProvider) >= 3

    def test_placement_strategy(self) -> None:
        assert PlacementStrategy.COST_OPTIMIZED == "cost_optimized"
        assert len(PlacementStrategy) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = MultiCloudOrchestratorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = MultiCloudOrchestratorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
