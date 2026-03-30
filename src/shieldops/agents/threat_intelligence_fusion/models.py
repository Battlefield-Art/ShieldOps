"""State models for the Threat Intelligence Fusion Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class TIFStage(StrEnum):
    """Workflow stages for threat intelligence fusion."""

    COLLECT_FEEDS = "collect_feeds"
    NORMALIZE_IOCS = "normalize_iocs"
    CORRELATE = "correlate"
    ENRICH = "enrich"
    SCORE = "score"
    REPORT = "report"


class IOCType(StrEnum):
    """Types of indicators of compromise."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CVE = "cve"
    MUTEX = "mutex"
    REGISTRY_KEY = "registry_key"


class ThreatLevel(StrEnum):
    """Threat severity levels for scored indicators."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# ── Domain Models ─────────────────────────────────────


class ThreatFeed(BaseModel):
    """A threat intelligence feed source."""

    feed_id: str = ""
    name: str = ""
    provider: str = ""
    format_type: str = ""
    last_updated: datetime | None = None
    ioc_count: int = 0
    reliability_score: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class NormalizedIOC(BaseModel):
    """A normalized indicator of compromise in STIX format."""

    ioc_id: str = ""
    ioc_type: IOCType = IOCType.IP_ADDRESS
    value: str = ""
    source_feed: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    stix_pattern: str = ""
    tags: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)


class Correlation(BaseModel):
    """A correlation between indicators from multiple sources."""

    correlation_id: str = ""
    ioc_ids: list[str] = Field(default_factory=list)
    source_count: int = 0
    campaign_name: str = ""
    threat_actor: str = ""
    confidence: float = 0.0
    technique_ids: list[str] = Field(default_factory=list)
    description: str = ""


class EnrichedIndicator(BaseModel):
    """An IOC enriched with additional context."""

    ioc_id: str = ""
    ioc_value: str = ""
    geo_location: str = ""
    asn: str = ""
    whois_info: str = ""
    related_campaigns: list[str] = Field(default_factory=list)
    related_malware: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)


class ThreatScore(BaseModel):
    """Scored threat indicator with priority."""

    ioc_id: str = ""
    ioc_value: str = ""
    threat_level: ThreatLevel = ThreatLevel.LOW
    score: float = 0.0
    source_count: int = 0
    confidence: float = 0.0
    actionable: bool = False
    reasoning: str = ""


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the threat intel fusion workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ThreatIntelligenceFusionState(BaseModel):
    """Full state for the Threat Intelligence Fusion workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: TIFStage = TIFStage.COLLECT_FEEDS
    fusion_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Collection
    collected_feeds: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_raw_iocs: int = 0

    # Normalization
    normalized_iocs: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    unique_ioc_count: int = 0

    # Correlation
    correlations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    campaign_count: int = 0

    # Enrichment
    enriched_indicators: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Scoring
    threat_scores: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    critical_threat_count: int = 0

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
