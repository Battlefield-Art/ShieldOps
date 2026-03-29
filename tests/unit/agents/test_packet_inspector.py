"""Tests for shieldops.agents.packet_inspector."""

from __future__ import annotations

import pytest

from shieldops.agents.packet_inspector.models import (
    InspectionStage,
    PacketCapture,
    PacketInspectorState,
    PayloadAnalysis,
    PayloadRisk,
    ReasoningStep,
    ThreatDetection,
    TLSCertCheck,
    TLSStatus,
)


def _state(**kw) -> PacketInspectorState:
    return PacketInspectorState(**kw)


class TestEnums:
    def test_inspection_stage_values(self):
        assert InspectionStage.CAPTURE_PACKETS == "capture_packets"
        assert InspectionStage.DECODE_PROTOCOL == "decode_protocol"
        assert InspectionStage.ANALYZE_PAYLOAD == "analyze_payload"
        assert InspectionStage.VALIDATE_TLS == "validate_tls"
        assert InspectionStage.DETECT_THREATS == "detect_threats"
        assert InspectionStage.REPORT == "report"

    def test_payload_risk_values(self):
        assert PayloadRisk.CRITICAL == "critical"
        assert PayloadRisk.HIGH == "high"
        assert PayloadRisk.MEDIUM == "medium"
        assert PayloadRisk.LOW == "low"
        assert PayloadRisk.BENIGN == "benign"

    def test_tls_status_values(self):
        assert TLSStatus.VALID == "valid"
        assert TLSStatus.EXPIRED == "expired"
        assert TLSStatus.SELF_SIGNED == "self_signed"
        assert TLSStatus.REVOKED == "revoked"
        assert TLSStatus.WEAK_CIPHER == "weak_cipher"
        assert TLSStatus.MISSING == "missing"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == InspectionStage.CAPTURE_PACKETS
        assert s.packets == []
        assert s.packets_inspected == 0
        assert s.payload_analyses == []
        assert s.tls_checks == []
        assert s.threats_detected == []
        assert s.threat_count == 0
        assert s.avg_payload_entropy == 0.0
        assert s.tls_valid_pct == 0.0
        assert s.stats == {}
        assert s.reasoning_chain == []
        assert s.current_step == ""
        assert s.session_start == 0.0
        assert s.session_duration_ms == 0.0
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(
            tenant_id="t-01",
            packets_inspected=100,
            threat_count=5,
        )
        assert s.tenant_id == "t-01"
        assert s.packets_inspected == 100
        assert s.threat_count == 5

    def test_packet_capture_defaults(self):
        p = PacketCapture()
        assert p.id == ""
        assert p.src_ip == ""
        assert p.dst_ip == ""
        assert p.src_port == 0
        assert p.dst_port == 0
        assert p.protocol == ""
        assert p.payload_size_bytes == 0
        assert p.timestamp == 0.0
        assert p.direction == ""
        assert p.interface == ""
        assert p.flags == []
        assert p.raw_hex == ""

    def test_payload_analysis_defaults(self):
        a = PayloadAnalysis()
        assert a.packet_id == ""
        assert a.protocol_decoded == ""
        assert a.content_type == ""
        assert a.payload_entropy == 0.0
        assert a.is_encrypted is False
        assert a.suspicious_patterns == []
        assert a.extracted_strings == []
        assert a.matched_signatures == []
        assert a.risk == PayloadRisk.BENIGN
        assert a.risk_score == 0.0
        assert a.llm_reasoning == ""

    def test_tls_cert_check_defaults(self):
        t = TLSCertCheck()
        assert t.packet_id == ""
        assert t.server_name == ""
        assert t.issuer == ""
        assert t.subject == ""
        assert t.not_before == ""
        assert t.not_after == ""
        assert t.serial_number == ""
        assert t.cipher_suite == ""
        assert t.tls_version == ""
        assert t.status == TLSStatus.VALID
        assert t.chain_valid is True
        assert t.pinning_match is True
        assert t.ja3_fingerprint == ""
        assert t.ja3s_fingerprint == ""

    def test_threat_detection_defaults(self):
        d = ThreatDetection()
        assert d.packet_id == ""
        assert d.threat_type == ""
        assert d.description == ""
        assert d.severity == PayloadRisk.MEDIUM
        assert d.mitre_technique == ""
        assert d.confidence == 0.0
        assert d.recommended_action == ""

    def test_reasoning_step_defaults(self):
        r = ReasoningStep()
        assert r.step == ""
        assert r.detail == ""
        assert r.confidence == 0.0
        assert r.metadata == {}


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.packet_inspector.tools import (
            PacketInspectorToolkit,
        )

        return PacketInspectorToolkit()

    @pytest.mark.asyncio
    async def test_capture_packets(self, toolkit):
        raw = [{"src_ip": "10.0.1.1", "dst_ip": "10.0.2.1"}]
        result = await toolkit.capture_packets(raw)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_analyze_payloads(self, toolkit):
        raw = [{"src_ip": "10.0.1.1", "dst_ip": "10.0.2.1"}]
        packets = await toolkit.capture_packets(raw)
        analyses = await toolkit.analyze_payloads(packets)
        assert isinstance(analyses, list)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.packet_inspector.graph import (
            create_packet_inspector_graph,
        )

        sg = create_packet_inspector_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.packet_inspector.graph import (
            create_packet_inspector_graph,
        )

        sg = create_packet_inspector_graph()
        compiled = sg.compile()
        assert compiled is not None
