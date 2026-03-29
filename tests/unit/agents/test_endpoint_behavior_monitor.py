"""Tests for shieldops.agents.endpoint_behavior_monitor."""

from __future__ import annotations

import pytest

from shieldops.agents.endpoint_behavior_monitor.models import (
    AnomalyType,
    EndpointBehaviorMonitorState,
    FileSystemEvent,
    MonitorStage,
    NetworkConnection,
    ProcessEvent,
    Severity,
)


def _state(**kw) -> EndpointBehaviorMonitorState:
    return EndpointBehaviorMonitorState(**kw)


class TestEnums:
    def test_monitor_stage_values(self):
        assert MonitorStage.COLLECT_TELEMETRY == "collect_telemetry"
        assert MonitorStage.ANALYZE_PROCESSES == "analyze_processes"
        assert MonitorStage.CHECK_FILESYSTEM == "check_filesystem"
        assert MonitorStage.INSPECT_REGISTRY == "inspect_registry"
        assert MonitorStage.INSPECT_NETWORK == "inspect_network"
        assert MonitorStage.CHECK_USB == "check_usb"
        assert MonitorStage.CORRELATE == "correlate"
        assert MonitorStage.REPORT == "report"

    def test_anomaly_type_values(self):
        assert AnomalyType.PROCESS_INJECTION == "process_injection"
        assert AnomalyType.SUSPICIOUS_EXECUTION == "suspicious_execution"
        assert AnomalyType.FILE_TAMPERING == "file_tampering"
        assert AnomalyType.REGISTRY_MODIFICATION == "registry_modification"
        assert AnomalyType.LATERAL_MOVEMENT == "lateral_movement"
        assert AnomalyType.DATA_EXFILTRATION == "data_exfiltration"
        assert AnomalyType.USB_VIOLATION == "usb_violation"
        assert AnomalyType.NORMAL == "normal"

    def test_severity_values(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.endpoint_id == ""
        assert s.stage == MonitorStage.COLLECT_TELEMETRY
        assert s.process_events == []
        assert s.filesystem_events == []
        assert s.registry_events == []
        assert s.network_events == []
        assert s.usb_events == []
        assert s.anomalies == []
        assert s.total_events == 0
        assert s.anomaly_count == 0
        assert s.risk_score == 0.0
        assert s.summary == ""
        assert s.recommendations == []
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(endpoint_id="EP-001", risk_score=72.5, anomaly_count=5)
        assert s.endpoint_id == "EP-001"
        assert s.risk_score == 72.5
        assert s.anomaly_count == 5

    def test_process_event_defaults(self):
        p = ProcessEvent()
        assert p.pid == 0
        assert p.name == ""
        assert p.severity == Severity.INFO
        assert p.anomaly_type == AnomalyType.NORMAL

    def test_filesystem_event_defaults(self):
        f = FileSystemEvent()
        assert f.path == ""
        assert f.action == ""
        assert f.severity == Severity.INFO

    def test_network_connection_defaults(self):
        n = NetworkConnection()
        assert n.src_ip == ""
        assert n.dst_ip == ""
        assert n.bytes_sent == 0


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.endpoint_behavior_monitor.tools import (
            EndpointBehaviorMonitorToolkit,
        )

        return EndpointBehaviorMonitorToolkit()

    @pytest.mark.asyncio
    async def test_collect_process_events(self, toolkit):
        result = await toolkit.collect_process_events("EP-001")
        assert isinstance(result, list)
        assert len(result) >= 2

    @pytest.mark.asyncio
    async def test_analyze_anomalies(self, toolkit):
        procs = await toolkit.collect_process_events("EP-001")
        fs = await toolkit.collect_filesystem_events("EP-001")
        reg = await toolkit.collect_registry_events("EP-001")
        net = await toolkit.collect_network_events("EP-001")
        usb = await toolkit.collect_usb_events("EP-001")
        anomalies, risk = await toolkit.analyze_anomalies(procs, fs, reg, net, usb)
        assert isinstance(anomalies, list)
        assert len(anomalies) > 0
        assert isinstance(risk, float)
        assert risk > 0.0


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.endpoint_behavior_monitor.graph import (
            create_endpoint_behavior_monitor_graph,
        )

        sg = create_endpoint_behavior_monitor_graph()
        assert sg.compile() is not None
