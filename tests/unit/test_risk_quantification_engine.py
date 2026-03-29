"""Tests for risk_quantification_engine."""

from __future__ import annotations

from shieldops.agents.risk_quantification_engine.models import (
    RiskCategory,
    RiskQuantificationEngineState,
    RiskTolerance,
    RQEStage,
)


class TestEnums:
    def test_stage(self) -> None:
        assert RQEStage.IDENTIFY_ASSETS == "identify_assets"
        assert len(RQEStage) >= 3

    def test_risk_category(self) -> None:
        assert RiskCategory.OPERATIONAL == "operational"
        assert len(RiskCategory) >= 3

    def test_risk_tolerance(self) -> None:
        assert RiskTolerance.AGGRESSIVE == "aggressive"
        assert len(RiskTolerance) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = RiskQuantificationEngineState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = RiskQuantificationEngineState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
