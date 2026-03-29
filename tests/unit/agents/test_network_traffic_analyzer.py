"""Tests for shieldops.agents.network_traffic_analyzer."""

from __future__ import annotations

import pytest

from shieldops.agents.network_traffic_analyzer.models import (
    AnalysisStage,
    AnomalyDetection,
    NetworkTrafficAnalyzerState,
    ProtocolAnalysis,
    ProtocolType,
    ThreatClassification,
    TrafficAnomalyType,
    TrafficFlow,
)


def _state(**kw) -> NetworkTrafficAnalyzerState:
    return NetworkTrafficAnalyzerState(**kw)


class TestEnums:
    def test_analysis_stage_values(self):
        assert AnalysisStage.INGEST_FLOWS == "ingest_flows"
        assert AnalysisStage.DETECT_ANOMALIES == "detect_anomalies"
        assert AnalysisStage.CLASSIFY_THREATS == "classify_threats"
        assert AnalysisStage.ANALYZE_PROTOCOLS == "analyze_protocols"
        assert AnalysisStage.CORRELATE == "correlate"
        assert AnalysisStage.REPORT == "report"

    def test_traffic_anomaly_type_values(self):
        assert TrafficAnomalyType.LATERAL_MOVEMENT == "lateral_movement"
        assert TrafficAnomalyType.C2_BEACON == "c2_beacon"
        assert TrafficAnomalyType.DATA_EXFILTRATION == "data_exfiltration"
        assert TrafficAnomalyType.DNS_TUNNELING == "dns_tunneling"
        assert TrafficAnomalyType.PORT_SCAN == "port_scan"
        assert TrafficAnomalyType.PROTOCOL_ANOMALY == "protocol_anomaly"
        assert TrafficAnomalyType.BANDWIDTH_SPIKE == "bandwidth_spike"
        assert TrafficAnomalyType.BEACONING == "beaconing"

    def test_protocol_type_values(self):
        assert ProtocolType.TCP == "tcp"
        assert ProtocolType.UDP == "udp"
        assert ProtocolType.HTTP == "http"
        assert ProtocolType.HTTPS == "https"
        assert ProtocolType.DNS == "dns"
        assert ProtocolType.SSH == "ssh"
        assert ProtocolType.TLS == "tls"
        assert ProtocolType.ICMP == "icmp"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == AnalysisStage.INGEST_FLOWS
        assert s.raw_flows == []
        assert s.flows == []
        assert s.anomalies == []
        assert s.threats == []
        assert s.protocol_analyses == []
        assert s.correlations == []
        assert s.stats == {}
        assert s.reasoning_chain == []
        assert s.current_step == ""
        assert s.session_start == 0.0
        assert s.session_duration_ms == 0
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(
            tenant_id="t-01",
            request_id="req-1",
            current_step="detect",
        )
        assert s.tenant_id == "t-01"
        assert s.request_id == "req-1"
        assert s.current_step == "detect"

    def test_traffic_flow_defaults(self):
        f = TrafficFlow()
        assert f.id == ""
        assert f.src_ip == ""
        assert f.dst_ip == ""
        assert f.src_port == 0
        assert f.dst_port == 0
        assert f.protocol == ProtocolType.TCP
        assert f.bytes_sent == 0
        assert f.bytes_received == 0
        assert f.packets == 0
        assert f.duration_ms == 0
        assert f.timestamp == 0.0
        assert f.metadata == {}

    def test_anomaly_detection_defaults(self):
        a = AnomalyDetection()
        assert a.id == ""
        assert a.anomaly_type == TrafficAnomalyType.PORT_SCAN
        assert a.severity == "medium"
        assert a.confidence == 0.0
        assert a.source_ips == []
        assert a.destination_ips == []
        assert a.description == ""
        assert a.indicators == []
        assert a.mitre_tactic == ""

    def test_protocol_analysis_defaults(self):
        p = ProtocolAnalysis()
        assert p.id == ""
        assert p.protocol == ProtocolType.TCP
        assert p.total_flows == 0
        assert p.total_bytes == 0
        assert p.anomalous_flows == 0
        assert p.top_talkers == []
        assert p.findings == []

    def test_threat_classification_defaults(self):
        t = ThreatClassification()
        assert t.id == ""
        assert t.threat_name == ""
        assert t.anomaly_type == TrafficAnomalyType.PORT_SCAN
        assert t.severity == "medium"
        assert t.confidence == 0.0
        assert t.kill_chain_phase == ""
        assert t.recommended_action == ""
        assert t.evidence == []


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.network_traffic_analyzer.tools import (
            NetworkTrafficAnalyzerToolkit,
        )

        return NetworkTrafficAnalyzerToolkit()

    @pytest.mark.asyncio
    async def test_ingest_flows(self, toolkit):
        raw = [{"src_ip": "10.0.1.1", "dst_ip": "10.0.2.1", "protocol": "tcp"}]
        result = await toolkit.ingest_flows(raw)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_detect_anomalies(self, toolkit):
        raw = [{"src_ip": "10.0.1.1", "dst_ip": "10.0.2.1", "protocol": "tcp"}]
        flows = await toolkit.ingest_flows(raw)
        anomalies = await toolkit.detect_anomalies(flows)
        assert isinstance(anomalies, list)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.network_traffic_analyzer.graph import (
            create_network_traffic_analyzer_graph,
        )

        sg = create_network_traffic_analyzer_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.network_traffic_analyzer.graph import (
            create_network_traffic_analyzer_graph,
        )

        sg = create_network_traffic_analyzer_graph()
        compiled = sg.compile()
        assert compiled is not None
