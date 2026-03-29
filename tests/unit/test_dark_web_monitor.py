"""Tests for dark_web_monitor."""

from __future__ import annotations

from shieldops.agents.dark_web_monitor.models import (
    DarkWebMonitorState,
    MonitorStage,
    SourceType,
)


class TestEnums:
    def test_monitorstage(self) -> None:
        assert MonitorStage.CRAWL_SOURCES == "crawl_sources"
        assert len(MonitorStage) >= 3

    def test_sourcetype(self) -> None:
        assert SourceType.PASTE_SITE == "paste_site"
        assert len(SourceType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = DarkWebMonitorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = DarkWebMonitorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
