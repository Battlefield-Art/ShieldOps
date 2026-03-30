"""Tests for deployment_guardian."""

from __future__ import annotations

from shieldops.agents.deployment_guardian.models import (
    DeploymentGuardianState,
    DeploymentPhase,
    DGStage,
    RiskLevel,
)


class TestEnums:
    def test_stage(self) -> None:
        assert DGStage.ANALYZE_CHANGES == "analyze_changes"
        assert len(DGStage) >= 3

    def test_deployment_phase(self) -> None:
        assert DeploymentPhase.BUILD == "build"
        assert len(DeploymentPhase) >= 3

    def test_risk_level(self) -> None:
        assert RiskLevel.CRITICAL == "critical"
        assert len(RiskLevel) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = DeploymentGuardianState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = DeploymentGuardianState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
