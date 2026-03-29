"""Tests for physical_access_monitor."""

from __future__ import annotations

from shieldops.agents.physical_access_monitor.models import (
    AccessType,
    AlertLevel,
    MonitorStage,
    PhysicalAccessMonitorState,
)


class TestEnums:
    def test_accesstype(self) -> None:
        assert AccessType.BADGE_SWIPE == "badge_swipe"
        assert len(AccessType) >= 3

    def test_alertlevel(self) -> None:
        assert AlertLevel.CRITICAL == "critical"
        assert len(AlertLevel) >= 3

    def test_monitorstage(self) -> None:
        assert MonitorStage.INGEST_EVENTS == "ingest_events"
        assert len(MonitorStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = PhysicalAccessMonitorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = PhysicalAccessMonitorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
