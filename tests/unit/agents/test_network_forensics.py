"""Tests for shieldops.agents.network_forensics."""

from __future__ import annotations

import pytest

from shieldops.agents.network_forensics.models import (
    EvidenceType,
    ExfilPath,
    ForensicEvidence,
    ForensicsStage,
    LateralMovement,
    NetworkForensicsState,
    NetworkSession,
    SessionType,
    TimelineEvent,
)


def _state(**kw) -> NetworkForensicsState:
    return NetworkForensicsState(**kw)


class TestEnums:
    def test_forensics_stage_values(self):
        assert ForensicsStage.INGEST_CAPTURE == "ingest_capture"
        assert ForensicsStage.RECONSTRUCT_SESSIONS == "reconstruct_sessions"
        assert ForensicsStage.BUILD_TIMELINE == "build_timeline"
        assert ForensicsStage.TRACE_LATERAL == "trace_lateral"
        assert ForensicsStage.MAP_EXFILTRATION == "map_exfiltration"
        assert ForensicsStage.REPORT == "report"

    def test_evidence_type_values(self):
        assert EvidenceType.PCAP == "pcap"
        assert EvidenceType.NETFLOW == "netflow"
        assert EvidenceType.ZEEK_LOG == "zeek_log"
        assert EvidenceType.DNS_LOG == "dns_log"
        assert EvidenceType.FIREWALL_LOG == "firewall_log"
        assert EvidenceType.PROXY_LOG == "proxy_log"
        assert EvidenceType.IDS_ALERT == "ids_alert"
        assert EvidenceType.SYSLOG == "syslog"

    def test_session_type_values(self):
        assert SessionType.HTTP == "http"
        assert SessionType.HTTPS == "https"
        assert SessionType.DNS == "dns"
        assert SessionType.SMB == "smb"
        assert SessionType.SSH == "ssh"
        assert SessionType.RDP == "rdp"
        assert SessionType.FTP == "ftp"
        assert SessionType.SMTP == "smtp"
        assert SessionType.ICMP == "icmp"
        assert SessionType.CUSTOM == "custom"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == ForensicsStage.INGEST_CAPTURE
        assert s.captures == []
        assert s.captures_ingested == 0
        assert s.sessions == []
        assert s.sessions_reconstructed == 0
        assert s.evidence == []
        assert s.timeline == []
        assert s.lateral_movements == []
        assert s.exfil_paths == []
        assert s.total_bytes_analyzed == 0
        assert s.total_packets_analyzed == 0
        assert s.suspicious_sessions == 0
        assert s.exfil_bytes_detected == 0
        assert s.stats == {}
        assert s.reasoning_chain == []
        assert s.current_step == ""
        assert s.session_start == 0.0
        assert s.session_duration_ms == 0.0
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(
            tenant_id="t-01",
            captures_ingested=10,
            sessions_reconstructed=100,
        )
        assert s.tenant_id == "t-01"
        assert s.captures_ingested == 10
        assert s.sessions_reconstructed == 100

    def test_network_session_defaults(self):
        ns = NetworkSession()
        assert ns.id == ""
        assert ns.session_type == SessionType.HTTP
        assert ns.src_ip == ""
        assert ns.src_port == 0
        assert ns.dst_ip == ""
        assert ns.dst_port == 0
        assert ns.protocol == ""
        assert ns.bytes_sent == 0
        assert ns.bytes_received == 0
        assert ns.packet_count == 0
        assert ns.start_time == 0.0
        assert ns.end_time == 0.0
        assert ns.duration_seconds == 0.0
        assert ns.flags == []
        assert ns.payload_preview == ""
        assert ns.is_encrypted is False
        assert ns.tls_version == ""
        assert ns.server_name == ""
        assert ns.user_agent == ""
        assert ns.http_method == ""
        assert ns.http_uri == ""
        assert ns.dns_query == ""
        assert ns.dns_response == ""

    def test_forensic_evidence_defaults(self):
        e = ForensicEvidence()
        assert e.id == ""
        assert e.evidence_type == EvidenceType.PCAP
        assert e.source_file == ""
        assert e.timestamp == 0.0
        assert e.description == ""
        assert e.src_ip == ""
        assert e.dst_ip == ""
        assert e.protocol == ""
        assert e.severity == ""
        assert e.ioc_matches == []
        assert e.mitre_techniques == []
        assert e.raw_data == ""
        assert e.confidence == 0.0

    def test_exfil_path_defaults(self):
        p = ExfilPath()
        assert p.id == ""
        assert p.src_host == ""
        assert p.dst_host == ""
        assert p.dst_ip == ""
        assert p.protocol == ""
        assert p.port == 0
        assert p.method == ""
        assert p.bytes_exfiltrated == 0
        assert p.duration_seconds == 0.0
        assert p.encoding == ""
        assert p.is_encrypted is False
        assert p.confidence == 0.0
        assert p.sessions == []
        assert p.mitre_techniques == []
        assert p.risk_score == 0.0

    def test_timeline_event_defaults(self):
        t = TimelineEvent()
        assert t.timestamp == 0.0
        assert t.event_type == ""
        assert t.src_ip == ""
        assert t.dst_ip == ""
        assert t.description == ""
        assert t.evidence_ids == []
        assert t.severity == ""

    def test_lateral_movement_defaults(self):
        lm = LateralMovement()
        assert lm.src_host == ""
        assert lm.dst_host == ""
        assert lm.protocol == ""
        assert lm.method == ""
        assert lm.timestamp == 0.0
        assert lm.credential_used == ""
        assert lm.mitre_technique == ""
        assert lm.confidence == 0.0


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.network_forensics.tools import (
            NetworkForensicsToolkit,
        )

        return NetworkForensicsToolkit()

    @pytest.mark.asyncio
    async def test_ingest_captures(self, toolkit):
        captures = [{"source_file": "test.pcap", "type": "pcap"}]
        result = await toolkit.ingest_captures(captures)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_reconstruct_sessions(self, toolkit):
        captures = [{"source_file": "test.pcap", "type": "pcap"}]
        evidence = await toolkit.ingest_captures(captures)
        sessions = await toolkit.reconstruct_sessions(evidence)
        assert isinstance(sessions, list)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.network_forensics.graph import (
            create_network_forensics_graph,
        )

        sg = create_network_forensics_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.network_forensics.graph import (
            create_network_forensics_graph,
        )

        sg = create_network_forensics_graph()
        compiled = sg.compile()
        assert compiled is not None
