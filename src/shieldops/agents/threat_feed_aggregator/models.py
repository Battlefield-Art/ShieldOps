"""Threat Feed Aggregator Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TFAStage(StrEnum):
    COLLECT_FEEDS = "collect_feeds"
    NORMALIZE_IOCS = "normalize_iocs"
    CORRELATE_THREATS = "correlate_threats"
    ENRICH_CONTEXT = "enrich_context"
    DISTRIBUTE_INTEL = "distribute_intel"
    REPORT = "report"


class FeedSource(StrEnum):
    MISP = "misp"
    STIX_TAXII = "stix_taxii"
    ALIENVAULT_OTX = "alienvault_otx"
    VIRUSTOTAL = "virustotal"
    ABUSE_IPDB = "abuse_ipdb"
    INTERNAL = "internal"


class IOCType(StrEnum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CVE = "cve"


class ThreatFeed(BaseModel):
    """A raw threat feed entry from a source."""

    id: str = ""
    source: FeedSource = FeedSource.MISP
    ioc_value: str = ""
    ioc_type: IOCType = IOCType.IP_ADDRESS
    severity: str = "medium"
    confidence: float = 0.0
    tags: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
    )


class NormalizedIOC(BaseModel):
    """A normalized indicator of compromise."""

    id: str = ""
    ioc_value: str = ""
    ioc_type: IOCType = IOCType.IP_ADDRESS
    sources: list[FeedSource] = Field(
        default_factory=list,
    )
    first_seen: str = ""
    last_seen: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    tags: list[str] = Field(default_factory=list)


class ThreatCorrelation(BaseModel):
    """A correlation between multiple IOCs."""

    id: str = ""
    ioc_ids: list[str] = Field(
        default_factory=list,
    )
    campaign_name: str = ""
    threat_actor: str = ""
    attack_pattern: str = ""
    confidence: float = 0.0
    mitre_techniques: list[str] = Field(
        default_factory=list,
    )


class EnrichedThreat(BaseModel):
    """An IOC enriched with additional context."""

    id: str = ""
    ioc_id: str = ""
    ioc_value: str = ""
    geo_location: str = ""
    asn: str = ""
    whois_org: str = ""
    malware_families: list[str] = Field(
        default_factory=list,
    )
    related_campaigns: list[str] = Field(
        default_factory=list,
    )
    risk_score: float = 0.0


class IntelDistribution(BaseModel):
    """A distribution record for threat intel."""

    id: str = ""
    target: str = ""
    format: str = "stix2.1"
    ioc_count: int = 0
    status: str = "pending"
    recipients: list[str] = Field(
        default_factory=list,
    )


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(
        default_factory=dict,
    )


class ThreatFeedAggregatorState(BaseModel):
    """Main state for the Threat Feed Aggregator."""

    request_id: str = ""
    tenant_id: str = ""
    stage: TFAStage = TFAStage.COLLECT_FEEDS

    feeds: list[ThreatFeed] = Field(
        default_factory=list,
    )
    normalized_iocs: list[NormalizedIOC] = Field(
        default_factory=list,
    )
    correlations: list[ThreatCorrelation] = Field(
        default_factory=list,
    )
    enriched_threats: list[EnrichedThreat] = Field(
        default_factory=list,
    )
    distributions: list[IntelDistribution] = Field(
        default_factory=list,
    )

    report: str = ""
    total_iocs: int = 0
    high_severity_count: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
