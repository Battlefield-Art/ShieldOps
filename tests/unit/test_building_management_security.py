"""Tests for building_management_security."""

from __future__ import annotations

from shieldops.agents.building_management_security.models import (
    BMSSystem,
    BuildingManagementSecurityState,
    RiskLevel,
    SecurityStage,
)


class TestEnums:
    def test_bmssystem(self) -> None:
        assert BMSSystem.HVAC == "hvac"
        assert len(BMSSystem) >= 3

    def test_risklevel(self) -> None:
        assert RiskLevel.CRITICAL == "critical"
        assert len(RiskLevel) >= 3

    def test_securitystage(self) -> None:
        assert SecurityStage.DISCOVER_SYSTEMS == "discover_systems"
        assert len(SecurityStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = BuildingManagementSecurityState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = BuildingManagementSecurityState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
