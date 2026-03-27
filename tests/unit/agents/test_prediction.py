"""Tests for shieldops.agents.prediction."""

from __future__ import annotations

from shieldops.agents.prediction.models import (
    PredictionSeverity,
    PredictionState,
)


class TestEnums:
    def test_predictionseverity_low(self):
        assert PredictionSeverity.LOW == "low"

    def test_predictionseverity_medium(self):
        assert PredictionSeverity.MEDIUM == "medium"

    def test_predictionseverity_high(self):
        assert PredictionSeverity.HIGH == "high"

    def test_predictionseverity_critical(self):
        assert PredictionSeverity.CRITICAL == "critical"


class TestModels:
    def test_state_defaults(self):
        s = PredictionState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.prediction.graph import (
            create_prediction_graph,
        )

        sg = create_prediction_graph()
        assert sg.compile() is not None
