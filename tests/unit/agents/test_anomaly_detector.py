"""Tests for shieldops.agents.anomaly_detector."""

from __future__ import annotations

from shieldops.agents.anomaly_detector.models import (
    AnomalyDetectorState,
    AnomalySeverity,
    AnomalyType,
    DetectionStage,
)


class TestEnums:
    def test_detectionstage_collect_data(self):
        assert DetectionStage.COLLECT_DATA == "collect_data"

    def test_detectionstage_detect_anomalies(self):
        assert DetectionStage.DETECT_ANOMALIES == "detect_anomalies"

    def test_detectionstage_classify(self):
        assert DetectionStage.CLASSIFY == "classify"

    def test_detectionstage_correlate(self):
        assert DetectionStage.CORRELATE == "correlate"

    def test_anomalytype_spike(self):
        assert AnomalyType.SPIKE == "spike"

    def test_anomalytype_drop(self):
        assert AnomalyType.DROP == "drop"

    def test_anomalytype_trend_change(self):
        assert AnomalyType.TREND_CHANGE == "trend_change"

    def test_anomalytype_seasonality_violation(self):
        assert AnomalyType.SEASONALITY_VIOLATION == "seasonality_violation"

    def test_anomalyseverity_critical(self):
        assert AnomalySeverity.CRITICAL == "critical"

    def test_anomalyseverity_high(self):
        assert AnomalySeverity.HIGH == "high"

    def test_anomalyseverity_medium(self):
        assert AnomalySeverity.MEDIUM == "medium"

    def test_anomalyseverity_low(self):
        assert AnomalySeverity.LOW == "low"


class TestModels:
    def test_state_defaults(self):
        s = AnomalyDetectorState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.anomaly_detector.graph import (
            create_anomaly_detector_graph,
        )

        sg = create_anomaly_detector_graph()
        assert sg.compile() is not None
