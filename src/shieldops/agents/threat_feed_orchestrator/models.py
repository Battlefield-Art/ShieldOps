"""State models for the Threat Feed Orchestrator Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class TFOStage(StrEnum):
    """Stages in the threat feed orchestration lifecycle."""

    CONNECT_FEEDS = "connect_feeds"
    NORMALIZE = "normalize"
    DEDUPLICATE = "deduplicate"
    ENRICH = "enrich"
    DISTRIBUTE = "distribute"
    REPORT = "report"


class FeedFormat(StrEnum):
    """Supported threat intelligence feed formats."""

    STIX_21 = "stix_21"
    STIX_20 = "stix_20"
    TAXII = "taxii"
    CSV = "csv"
    JSON = "json"
    MISP = "misp"


class IndicatorType(StrEnum):
    """Types of threat indicators (IOCs)."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CVE = "cve"


# --- Domain models ---


class FeedConnection(BaseModel):
    """A connected threat intelligence feed source."""

    feed_id: str = ""
    name: str = ""
    feed_format: FeedFormat = FeedFormat.STIX_21
    url: str = ""
    status: str = "disconnected"
    last_poll: datetime | None = None
    indicator_count: int = 0
    confidence: float = 0.0


class NormalizedIndicator(BaseModel):
    """A normalized threat indicator in STIX format."""

    indicator_id: str = ""
    indicator_type: IndicatorType = IndicatorType.IP_ADDRESS
    value: str = ""
    source_feed: str = ""
    confidence: float = 0.0
    severity: str = "medium"
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class EnrichmentResult(BaseModel):
    """Enrichment data for a threat indicator."""

    indicator_id: str = ""
    enrichment_sources: list[str] = Field(
        default_factory=list,
    )
    geo_location: str = ""
    threat_actor: str = ""
    campaign: str = ""
    mitre_techniques: list[str] = Field(
        default_factory=list,
    )
    risk_score: float = 0.0


class DistributionResult(BaseModel):
    """Result of distributing indicators to consumers."""

    consumer_id: str = ""
    consumer_name: str = ""
    indicators_sent: int = 0
    format: str = ""
    success: bool = False
    delivery_time_ms: int = 0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the orchestrator workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ThreatFeedOrchestratorState(BaseModel):
    """Full state for a threat feed orchestrator run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: TFOStage = TFOStage.CONNECT_FEEDS

    # Inputs
    feed_urls: list[str] = Field(default_factory=list)
    feed_configs: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    consumer_configs: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    enrichment_sources: list[str] = Field(
        default_factory=list,
    )

    # Pipeline fields
    feed_connections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    normalized_indicators: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    deduplicated_indicators: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    enriched_indicators: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    distribution_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_indicators: int = 0
    unique_indicators: int = 0
    enriched_count: int = 0
    distributed_count: int = 0
    dedup_ratio: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
