"""Unit tests for threat_feed_manager agent."""

from __future__ import annotations

import pytest

from shieldops.agents.threat_feed_manager.models import (
    FeedHealth,
    FeedScore,
    FeedStage,
    FeedType,
    NormalizedIOC,
    ThreatFeed,
    ThreatFeedManagerState,
)
from shieldops.agents.threat_feed_manager.tools import (
    FEED_REGISTRY,
    ThreatFeedManagerToolkit,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_feed_stage_values(self):
        assert FeedStage.INGEST_FEEDS == "ingest_feeds"
        assert FeedStage.NORMALIZE == "normalize"
        assert FeedStage.DEDUPLICATE == "deduplicate"
        assert FeedStage.SCORE == "score"
        assert FeedStage.ENRICH == "enrich"
        assert FeedStage.REPORT == "report"

    def test_feed_type_values(self):
        assert FeedType.STIX_TAXII == "stix_taxii"
        assert FeedType.MISP == "misp"
        assert FeedType.COMMERCIAL == "commercial"
        assert FeedType.OSINT == "osint"
        assert FeedType.ISAC == "isac"
        assert FeedType.CUSTOM == "custom"

    def test_feed_health_values(self):
        assert FeedHealth.HEALTHY == "healthy"
        assert FeedHealth.DEGRADED == "degraded"
        assert FeedHealth.STALE == "stale"
        assert FeedHealth.OFFLINE == "offline"
        assert FeedHealth.ERROR == "error"


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class TestState:
    def test_defaults(self):
        state = ThreatFeedManagerState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.error == ""
        assert state.stage == FeedStage.INGEST_FEEDS
        assert state.feeds == []
        assert state.normalized_iocs == []
        assert state.feed_scores == []
        assert state.reasoning_chain == []
        assert state.session_start == 0.0
        assert state.session_duration_ms == 0

    def test_with_values(self):
        state = ThreatFeedManagerState(
            request_id="tfm-1",
            tenant_id="t-1",
        )
        assert state.request_id == "tfm-1"
        assert state.tenant_id == "t-1"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_threat_feed_defaults(self):
        feed = ThreatFeed()
        assert feed.id == ""
        assert feed.feed_type == FeedType.OSINT
        assert feed.health == FeedHealth.HEALTHY
        assert feed.ioc_count == 0
        assert feed.raw_data == []
        assert feed.error == ""

    def test_normalized_ioc_defaults(self):
        ioc = NormalizedIOC()
        assert ioc.ioc_type == ""
        assert ioc.value == ""
        assert ioc.confidence == 0.0
        assert ioc.tags == []
        assert ioc.enrichment == {}

    def test_feed_score_defaults(self):
        score = FeedScore()
        assert score.feed_id == ""
        assert score.reliability == 0.0
        assert score.overall_score == 0.0
        assert score.recommendation == ""


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        return ThreatFeedManagerToolkit()

    @pytest.mark.asyncio
    async def test_ingest_feeds(self, toolkit):
        feeds = await toolkit.ingest_feeds()
        assert len(feeds) == len(FEED_REGISTRY)
        for feed in feeds:
            assert isinstance(feed, ThreatFeed)
            assert feed.id.startswith("feed-")
            assert feed.health == FeedHealth.HEALTHY
            assert feed.ioc_count > 0

    @pytest.mark.asyncio
    async def test_normalize_iocs(self, toolkit):
        feeds = await toolkit.ingest_feeds()
        iocs = await toolkit.normalize_iocs(feeds)
        assert len(iocs) > 0
        for ioc in iocs:
            assert isinstance(ioc, NormalizedIOC)
            assert ioc.id.startswith("ioc-")
            assert ioc.source_feed != ""

    @pytest.mark.asyncio
    async def test_deduplicate(self, toolkit):
        iocs = [
            NormalizedIOC(ioc_type="ip", value="10.0.0.1", confidence=0.8),
            NormalizedIOC(ioc_type="ip", value="10.0.0.1", confidence=0.9),
            NormalizedIOC(ioc_type="ip", value="10.0.0.2", confidence=0.7),
        ]
        deduped = await toolkit.deduplicate(iocs)
        assert len(deduped) == 2
        # Should keep highest confidence for 10.0.0.1
        match = [i for i in deduped if i.value == "10.0.0.1"]
        assert len(match) == 1
        assert match[0].confidence == 0.9

    @pytest.mark.asyncio
    async def test_score_feeds(self, toolkit):
        feeds = await toolkit.ingest_feeds()
        iocs = await toolkit.normalize_iocs(feeds)
        scores = await toolkit.score_feeds(feeds, iocs)
        assert len(scores) == len(feeds)
        for s in scores:
            assert isinstance(s, FeedScore)
            assert s.id.startswith("score-")
            assert 0.0 <= s.overall_score <= 1.0
            assert s.recommendation in ("keep", "deprioritize", "remove")

    @pytest.mark.asyncio
    async def test_enrich_iocs(self, toolkit):
        iocs = [
            NormalizedIOC(ioc_type="ip", value="10.0.0.1"),
            NormalizedIOC(ioc_type="domain", value="evil.com"),
        ]
        enriched = await toolkit.enrich_iocs(iocs)
        assert len(enriched) == 2
        for ioc in enriched:
            assert "reputation" in ioc.enrichment


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


class TestNodes:
    @pytest.mark.asyncio
    async def test_ingest_feeds_node(self):
        from shieldops.agents.threat_feed_manager.nodes import (
            ingest_feeds,
            set_toolkit,
        )

        set_toolkit(ThreatFeedManagerToolkit())
        state = ThreatFeedManagerState(request_id="req-1")
        result = await ingest_feeds(state)
        assert "feeds" in result
        assert result["stage"] == FeedStage.NORMALIZE
        assert len(result["reasoning_chain"]) > 0

    @pytest.mark.asyncio
    async def test_normalize_node(self):
        from shieldops.agents.threat_feed_manager.nodes import (
            normalize,
            set_toolkit,
        )

        set_toolkit(ThreatFeedManagerToolkit())
        feed = ThreatFeed(
            name="test",
            raw_data=[{"type": "ip", "value": "1.2.3.4", "confidence": 0.8}],
        )
        state = ThreatFeedManagerState(
            request_id="req-1",
            feeds=[feed],
        )
        result = await normalize(state)
        assert "normalized_iocs" in result
        assert result["stage"] == FeedStage.DEDUPLICATE

    @pytest.mark.asyncio
    async def test_deduplicate_node(self):
        from shieldops.agents.threat_feed_manager.nodes import (
            deduplicate,
            set_toolkit,
        )

        set_toolkit(ThreatFeedManagerToolkit())
        iocs = [
            NormalizedIOC(ioc_type="ip", value="1.1.1.1", confidence=0.5),
            NormalizedIOC(ioc_type="ip", value="1.1.1.1", confidence=0.9),
        ]
        state = ThreatFeedManagerState(
            request_id="req-1",
            normalized_iocs=iocs,
        )
        result = await deduplicate(state)
        assert len(result["normalized_iocs"]) == 1
        assert result["stage"] == FeedStage.SCORE

    @pytest.mark.asyncio
    async def test_score_node(self):
        from shieldops.agents.threat_feed_manager.nodes import (
            score,
            set_toolkit,
        )

        set_toolkit(ThreatFeedManagerToolkit())
        feed = ThreatFeed(
            name="test",
            health=FeedHealth.HEALTHY,
            ioc_count=5,
            last_poll_ts=1000000000.0,
        )
        ioc = NormalizedIOC(
            source_feed="test",
            confidence=0.8,
        )
        state = ThreatFeedManagerState(
            request_id="req-1",
            feeds=[feed],
            normalized_iocs=[ioc],
        )
        result = await score(state)
        assert "feed_scores" in result
        assert result["stage"] == FeedStage.ENRICH

    @pytest.mark.asyncio
    async def test_report_node(self):
        import time

        from shieldops.agents.threat_feed_manager.nodes import (
            report,
            set_toolkit,
        )

        set_toolkit(ThreatFeedManagerToolkit())
        state = ThreatFeedManagerState(
            request_id="req-1",
            session_start=time.time(),
            feeds=[ThreatFeed(name="test", health=FeedHealth.HEALTHY)],
            normalized_iocs=[NormalizedIOC(confidence=0.9)],
            feed_scores=[FeedScore(recommendation="keep")],
        )
        result = await report(state)
        assert result["stage"] == FeedStage.REPORT
        assert "session_duration_ms" in result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class TestRunner:
    def test_runner_init(self):
        from shieldops.agents.threat_feed_manager.runner import (
            ThreatFeedManagerRunner,
        )

        runner = ThreatFeedManagerRunner()
        assert runner is not None
