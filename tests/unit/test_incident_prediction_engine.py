"""Tests for incident_prediction_engine."""

from __future__ import annotations

from shieldops.agents.incident_prediction_engine.models import (
    ConfidenceLevel,
    IncidentPredictionEngineState,
    PredictionStage,
    PredictionType,
)


class TestEnums:
    def test_confidencelevel(self) -> None:
        assert ConfidenceLevel.HIGH == "high"
        assert len(ConfidenceLevel) >= 3

    def test_predictionstage(self) -> None:
        assert PredictionStage.COLLECT_SIGNALS == "collect_signals"
        assert len(PredictionStage) >= 3

    def test_predictiontype(self) -> None:
        assert PredictionType.RANSOMWARE == "ransomware"
        assert len(PredictionType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = IncidentPredictionEngineState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = IncidentPredictionEngineState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
