"""Unit tests for endpoint_behavior_monitor."""

from __future__ import annotations

from shieldops.agents.endpoint_behavior_monitor.models import (
    AnomalyType,
    EndpointBehaviorMonitorState,
    MonitorStage,
    Severity,
)


class TestEnums:
    def test_anomalytype(self) -> None:
        assert AnomalyType.PROCESS_INJECTION == "process_injection"
        assert len(AnomalyType) >= 3

    def test_monitorstage(self) -> None:
        assert MonitorStage.COLLECT_TELEMETRY == "collect_telemetry"
        assert len(MonitorStage) >= 3

    def test_severity(self) -> None:
        assert Severity.CRITICAL == "critical"
        assert len(Severity) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = EndpointBehaviorMonitorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = EndpointBehaviorMonitorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
