"""Unit tests for sca_dependency_checker."""

from __future__ import annotations

from shieldops.agents.sca_dependency_checker.models import (
    DependencyRisk,
    LicenseType,
    SCADependencyCheckerState,
    SCAStage,
)


class TestEnums:
    def test_dependencyrisk(self) -> None:
        assert DependencyRisk.CRITICAL == "critical"
        assert len(DependencyRisk) >= 3

    def test_licensetype(self) -> None:
        assert LicenseType.MIT == "mit"
        assert len(LicenseType) >= 3

    def test_scastage(self) -> None:
        assert SCAStage.DISCOVER_MANIFESTS == "discover_manifests"
        assert len(SCAStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SCADependencyCheckerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SCADependencyCheckerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
