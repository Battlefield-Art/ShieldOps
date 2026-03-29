"""Tests for sla_breach_predictor."""

from __future__ import annotations

from shieldops.agents.sla_breach_predictor.models import (
    BreachRisk,
    PredictionStage,
    SlaBreachPredictorState,
    SLAMetric,
)


class TestEnums:
    def test_breachrisk(self) -> None:
        assert BreachRisk.IMMINENT == "imminent"
        assert len(BreachRisk) >= 3

    def test_predictionstage(self) -> None:
        assert PredictionStage.COLLECT_TICKETS == "collect_tickets"
        assert len(PredictionStage) >= 3

    def test_slametric(self) -> None:
        assert SLAMetric.RESPONSE_TIME == "response_time"
        assert len(SLAMetric) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SlaBreachPredictorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SlaBreachPredictorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
