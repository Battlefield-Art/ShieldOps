"""Tests for finops_forecaster."""

from __future__ import annotations

from shieldops.agents.finops_forecaster.models import (
    FFStage,
    FinopsForecasterState,
    ForecastConfidence,
    ForecastHorizon,
)


class TestEnums:
    def test_stage(self) -> None:
        assert FFStage.COLLECT_HISTORICAL == "collect_historical"
        assert len(FFStage) >= 3

    def test_forecast_horizon(self) -> None:
        assert ForecastHorizon.DAILY == "daily"
        assert len(ForecastHorizon) >= 3

    def test_forecast_confidence(self) -> None:
        assert ForecastConfidence.VERY_HIGH == "very_high"
        assert len(ForecastConfidence) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = FinopsForecasterState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = FinopsForecasterState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
