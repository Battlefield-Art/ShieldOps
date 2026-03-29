"""Unit tests for bandwidth_anomaly_detector agent."""

from __future__ import annotations

from shieldops.agents.bandwidth_anomaly_detector.models import (
    AnomalyAlert,
    AnomalyCategory,
    BandwidthAnomalyDetectorState,
    BandwidthSample,
    DetectionStage,
)
from shieldops.agents.bandwidth_anomaly_detector.tools import BandwidthAnomalyDetectorToolkit


class TestEnums:
    def test_anomalycategory(self) -> None:
        assert AnomalyCategory.TRAFFIC_SPIKE == "traffic_spike"
        assert len(AnomalyCategory) >= 3

    def test_detectionstage(self) -> None:
        assert DetectionStage.COLLECT_SAMPLES == "collect_samples"
        assert len(DetectionStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        state = BandwidthAnomalyDetectorState()
        assert state.request_id == ""
        assert state.error == ""

    def test_with_values(self) -> None:
        state = BandwidthAnomalyDetectorState(
            request_id="t-1",
            tenant_id="t-1",
        )
        assert state.request_id == "t-1"


class TestAnomalyAlert:
    def test_defaults(self) -> None:
        obj = AnomalyAlert()
        assert obj is not None


class TestBandwidthSample:
    def test_defaults(self) -> None:
        obj = BandwidthSample()
        assert obj is not None


class TestToolkit:
    def test_init(self) -> None:
        tk = BandwidthAnomalyDetectorToolkit()
        assert tk is not None
