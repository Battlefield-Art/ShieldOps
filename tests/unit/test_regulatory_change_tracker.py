"""Tests for regulatory_change_tracker."""

from __future__ import annotations

from shieldops.agents.regulatory_change_tracker.models import (
    ImpactLevel,
    RCTStage,
    RegulationType,
    RegulatoryChangeTrackerState,
)


class TestEnums:
    def test_stage(self) -> None:
        assert RCTStage.SCAN_SOURCES == "scan_sources"
        assert len(RCTStage) >= 3

    def test_regulation_type(self) -> None:
        assert RegulationType.GDPR == "gdpr"
        assert len(RegulationType) >= 3

    def test_impact_level(self) -> None:
        assert ImpactLevel.CRITICAL == "critical"
        assert len(ImpactLevel) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = RegulatoryChangeTrackerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = RegulatoryChangeTrackerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
