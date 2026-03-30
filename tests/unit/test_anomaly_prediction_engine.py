"""Tests for anomaly_prediction_engine."""

from __future__ import annotations

from shieldops.agents.anomaly_prediction_engine.models import (
    AnomalyPredictionEngineState,
    APEStage,
    MetricDomain,
    PredictionConfidence,
)


class TestEnums:
    def test_stage(self) -> None:
        assert APEStage.INGEST_METRICS == "ingest_metrics"
        assert len(APEStage) >= 3

    def test_metric_domain(self) -> None:
        assert MetricDomain.INFRASTRUCTURE == "infrastructure"
        assert len(MetricDomain) >= 3

    def test_prediction_confidence(self) -> None:
        assert PredictionConfidence.VERY_HIGH == "very_high"
        assert len(PredictionConfidence) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = AnomalyPredictionEngineState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = AnomalyPredictionEngineState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
