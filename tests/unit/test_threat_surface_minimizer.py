"""Tests for threat_surface_minimizer."""

from __future__ import annotations

from shieldops.agents.threat_surface_minimizer.models import (
    ExposureLevel,
    MinimizationStage,
    ThreatSurfaceMinimizerState,
)


class TestEnums:
    def test_exposurelevel(self) -> None:
        assert ExposureLevel.INTERNET_FACING == "internet_facing"
        assert len(ExposureLevel) >= 3

    def test_minimizationstage(self) -> None:
        assert MinimizationStage.DISCOVER_SURFACE == "discover_surface"
        assert len(MinimizationStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ThreatSurfaceMinimizerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ThreatSurfaceMinimizerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
