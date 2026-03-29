"""Tests for cctv_analytics."""

from __future__ import annotations

from shieldops.agents.cctv_analytics.models import (
    AnalyticsStage,
    CameraStatus,
    CCTVAnalyticsState,
    DetectionType,
)


class TestEnums:
    def test_analyticsstage(self) -> None:
        assert AnalyticsStage.COLLECT_FEEDS == "collect_feeds"
        assert len(AnalyticsStage) >= 3

    def test_camerastatus(self) -> None:
        assert CameraStatus.ONLINE == "online"
        assert len(CameraStatus) >= 3

    def test_detectiontype(self) -> None:
        assert DetectionType.MOTION == "motion"
        assert len(DetectionType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = CCTVAnalyticsState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = CCTVAnalyticsState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
