"""State models for the Threat Feed Manager Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class FeedStage(StrEnum):
    """Stages in the threat feed management workflow."""

    INGEST_FEEDS = "ingest_feeds"
    NORMALIZE = "normalize"
    DEDUPLICATE = "deduplicate"
    SCORE = "score"
    ENRICH = "enrich"
    REPORT = "report"


class FeedType(StrEnum):
    """Threat intelligence feed types."""

    STIX_TAXII = "stix_taxii"
    MISP = "misp"
    COMMERCIAL = "commercial"
    OSINT = "osint"
    ISAC = "isac"
    CUSTOM = "custom"


class FeedHealth(StrEnum):
    """Health status of a threat feed."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    STALE = "stale"
    OFFLINE = "offline"
    ERROR = "error"


class ThreatFeed(BaseModel):
    """A threat intelligence feed source."""

    id: str = ""
    name: str = ""
    feed_type: FeedType = FeedType.OSINT
    url: str = ""
    health: FeedHealth = FeedHealth.HEALTHY
    ioc_count: int = 0
    last_poll_ts: float = 0.0
    error: str = ""
    raw_data: list[dict[str, Any]] = Field(default_factory=list)


class NormalizedIOC(BaseModel):
    """A normalized indicator of compromise."""

    id: str = ""
    ioc_type: str = ""
    value: str = ""
    source_feed: str = ""
    confidence: float = 0.0
    severity: str = "medium"
    tags: list[str] = Field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    enrichment: dict[str, Any] = Field(default_factory=dict)


class FeedScore(BaseModel):
    """Scoring result for a threat feed."""

    id: str = ""
    feed_id: str = ""
    feed_name: str = ""
    reliability: float = 0.0
    freshness: float = 0.0
    coverage: float = 0.0
    overall_score: float = 0.0
    recommendation: str = ""


class ThreatFeedManagerState(BaseModel):
    """Full state for the Threat Feed Manager workflow."""

    request_id: str = ""
    stage: FeedStage = FeedStage.INGEST_FEEDS
    tenant_id: str = ""

    # Feed data
    feeds: list[ThreatFeed] = Field(default_factory=list)
    normalized_iocs: list[NormalizedIOC] = Field(default_factory=list)
    feed_scores: list[FeedScore] = Field(default_factory=list)

    # Stats & reporting
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)

    # Workflow metadata
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: int = 0
    error: str = ""
