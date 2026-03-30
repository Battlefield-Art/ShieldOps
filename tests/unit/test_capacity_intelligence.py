"""Tests for capacity_intelligence."""

from __future__ import annotations

from shieldops.agents.capacity_intelligence.models import (
    CapacityIntelligenceState,
    CapacityRisk,
    CIStage,
    ResourceType,
)


class TestEnums:
    def test_stage(self) -> None:
        assert CIStage.COLLECT_UTILIZATION == "collect_utilization"
        assert len(CIStage) >= 3

    def test_resource_type(self) -> None:
        assert ResourceType.COMPUTE == "compute"
        assert len(ResourceType) >= 3

    def test_capacity_risk(self) -> None:
        assert CapacityRisk.CRITICAL == "critical"
        assert len(CapacityRisk) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = CapacityIntelligenceState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = CapacityIntelligenceState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
