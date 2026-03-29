"""Tests for privacy_engineering."""

from __future__ import annotations

from shieldops.agents.privacy_engineering.models import (
    PrivacyEngineeringState,
    PrivacyStage,
    PrivacyTechnique,
    RiskLevel,
)


class TestEnums:
    def test_privacy_stage(self) -> None:
        assert PrivacyStage.SCAN_PIPELINES == "scan_pipelines"
        assert len(PrivacyStage) >= 3

    def test_privacy_technique(self) -> None:
        assert PrivacyTechnique.DIFFERENTIAL_PRIVACY == "differential_privacy"
        assert len(PrivacyTechnique) >= 3

    def test_risk_level(self) -> None:
        assert RiskLevel.CRITICAL == "critical"
        assert len(RiskLevel) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = PrivacyEngineeringState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = PrivacyEngineeringState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
