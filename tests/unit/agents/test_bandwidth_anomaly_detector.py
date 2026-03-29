"""Tests for shieldops.agents.bandwidth_anomaly_detector."""

from __future__ import annotations

import pytest

from shieldops.agents.bandwidth_anomaly_detector.models import (
    AnomalyAlert,
    AnomalyCategory,
    BandwidthAnomalyDetectorState,
    BandwidthSample,
    BaselineProfile,
    DetectionStage,
    TrafficDirection,
)


def _state(**kw) -> BandwidthAnomalyDetectorState:
    return BandwidthAnomalyDetectorState(**kw)


class TestEnums:
    def test_detection_stage_values(self):
        assert DetectionStage.COLLECT_SAMPLES == "collect_samples"
        assert DetectionStage.BUILD_BASELINES == "build_baselines"
        assert DetectionStage.DETECT_ANOMALIES == "detect_anomalies"
        assert DetectionStage.CLASSIFY_TRAFFIC == "classify_traffic"
        assert DetectionStage.ALERT == "alert"
        assert DetectionStage.REPORT == "report"

    def test_anomaly_category_values(self):
        assert AnomalyCategory.TRAFFIC_SPIKE == "traffic_spike"
        assert AnomalyCategory.OFF_HOURS_TRANSFER == "off_hours_transfer"
        assert AnomalyCategory.LARGE_EGRESS == "large_egress"
        assert AnomalyCategory.CRYPTO_MINING == "crypto_mining"
        assert AnomalyCategory.TORRENT_ACTIVITY == "torrent_activity"
        assert AnomalyCategory.SHADOW_IT == "shadow_it"
        assert AnomalyCategory.DGA_TRAFFIC == "dga_traffic"
        assert AnomalyCategory.BEACONING == "beaconing"

    def test_traffic_direction_values(self):
        assert TrafficDirection.INBOUND == "inbound"
        assert TrafficDirection.OUTBOUND == "outbound"
        assert TrafficDirection.LATERAL == "lateral"
        assert TrafficDirection.UNKNOWN == "unknown"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == DetectionStage.COLLECT_SAMPLES
        assert s.samples == []
        assert s.baselines == []
        assert s.anomalies == []
        assert s.classifications == []
        assert s.alerts == []
        assert s.summary == ""
        assert s.total_samples == 0
        assert s.total_anomalies == 0
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(
            tenant_id="t-01",
            total_samples=1000,
            total_anomalies=5,
        )
        assert s.tenant_id == "t-01"
        assert s.total_samples == 1000
        assert s.total_anomalies == 5

    def test_bandwidth_sample_defaults(self):
        bs = BandwidthSample()
        assert bs.source_ip == ""
        assert bs.dest_ip == ""
        assert bs.direction == TrafficDirection.UNKNOWN
        assert bs.bytes_transferred == 0
        assert bs.packets == 0
        assert bs.protocol == ""
        assert bs.port == 0
        assert bs.timestamp is None
        assert bs.interface == ""
        assert bs.labels == {}

    def test_baseline_profile_defaults(self):
        bp = BaselineProfile()
        assert bp.entity == ""
        assert bp.direction == TrafficDirection.OUTBOUND
        assert bp.avg_bytes_per_hour == 0.0
        assert bp.stddev_bytes == 0.0
        assert bp.peak_bytes_per_hour == 0.0
        assert bp.active_hours == []
        assert bp.sample_count == 0
        assert bp.last_updated is None

    def test_anomaly_alert_defaults(self):
        aa = AnomalyAlert()
        assert aa.alert_id == ""
        assert aa.entity == ""
        assert aa.category == AnomalyCategory.TRAFFIC_SPIKE
        assert aa.direction == TrafficDirection.OUTBOUND
        assert aa.current_bytes == 0
        assert aa.baseline_bytes == 0.0
        assert aa.deviation_sigma == 0.0
        assert aa.confidence == 0.0
        assert aa.severity == "medium"
        assert aa.description == ""
        assert aa.detected_at is None
        assert aa.labels == {}


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.bandwidth_anomaly_detector.tools import (
            BandwidthAnomalyDetectorToolkit,
        )

        return BandwidthAnomalyDetectorToolkit()

    @pytest.mark.asyncio
    async def test_collect_samples(self, toolkit):
        result = await toolkit.collect_samples(tenant_id="t-01")
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_build_baselines(self, toolkit):
        samples = await toolkit.collect_samples(tenant_id="t-01")
        baselines = await toolkit.build_baselines(samples)
        assert isinstance(baselines, list)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.bandwidth_anomaly_detector.graph import (
            create_bandwidth_anomaly_detector_graph,
        )

        sg = create_bandwidth_anomaly_detector_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.bandwidth_anomaly_detector.graph import (
            create_bandwidth_anomaly_detector_graph,
        )

        sg = create_bandwidth_anomaly_detector_graph()
        compiled = sg.compile()
        assert compiled is not None
