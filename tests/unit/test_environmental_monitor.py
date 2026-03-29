"""Tests for environmental_monitor."""

from __future__ import annotations

from shieldops.agents.environmental_monitor.models import (
    EnvironmentalMonitorState,
    MonitorStage,
    SensorType,
)


class TestEnums:
    def test_monitorstage(self) -> None:
        assert MonitorStage.COLLECT_READINGS == "collect_readings"
        assert len(MonitorStage) >= 3

    def test_sensortype(self) -> None:
        assert SensorType.TEMPERATURE == "temperature"
        assert len(SensorType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = EnvironmentalMonitorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = EnvironmentalMonitorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
