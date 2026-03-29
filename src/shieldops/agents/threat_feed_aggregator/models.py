"""State models for the Threat Feed Aggregator Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TFAStage(StrEnum):
    """Stages of the threat feed aggregation workflow."""

    DISCOVER_FEEDS = "discover_feeds"
    INGEST_INDICATORS = "ingest_indicators"
    NORMALIZE_DATA = "normalize_data"
    DEDUPLICATE = "deduplicate"
    SCORE_RELEVANCE = "score_relevance"
    REPORT = "report"


class FeedSource(StrEnum):
    """Sources of threat intelligence feeds."""

    STIX_TAXII = "stix_taxii"
    MISP = "misp"
    OSINT = "osint"
    COMMERCIAL = "commercial"
    GOVERNMENT = "government"
    ISAC = "isac"


class IndicatorQuality(StrEnum):
    """Quality levels for ingested indicators."""

    VERIFIED = "verified"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"


class ThreatFeedAggregatorState(BaseModel):
    """Full state for threat feed aggregation."""

    request_id: str = ""
    stage: TFAStage = TFAStage.DISCOVER_FEEDS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    stats: dict[str, Any] = Field(
        default_factory=dict,
    )
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
