"""Tests for threat_feed_aggregator."""

from __future__ import annotations

from shieldops.agents.threat_feed_aggregator.models import (
    FeedSource,
    IndicatorQuality,
    TFAStage,
    ThreatFeedAggregatorState,
)


class TestEnums:
    def test_stage(self) -> None:
        assert TFAStage.DISCOVER_FEEDS == "discover_feeds"
        assert len(TFAStage) >= 3

    def test_feed_source(self) -> None:
        assert FeedSource.STIX_TAXII == "stix_taxii"
        assert len(FeedSource) >= 3

    def test_indicator_quality(self) -> None:
        assert IndicatorQuality.VERIFIED == "verified"
        assert len(IndicatorQuality) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ThreatFeedAggregatorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ThreatFeedAggregatorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
