"""LLM prompt templates for the Threat Intelligence Fusion Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class FeedCollectionOutput(BaseModel):
    """Structured output for feed collection analysis."""

    total_feeds: int = Field(
        description="Total feeds collected",
    )
    total_raw_iocs: int = Field(
        description="Total raw IOCs ingested",
    )
    summary: str = Field(
        description="Collection summary",
    )


class NormalizationOutput(BaseModel):
    """Structured output for IOC normalization."""

    unique_iocs: int = Field(
        description="Unique IOCs after dedup",
    )
    duplicates_removed: int = Field(
        description="Duplicate IOCs removed",
    )
    reasoning: str = Field(
        description="Normalization reasoning",
    )


class CorrelationOutput(BaseModel):
    """Structured output for IOC correlation."""

    correlations_found: int = Field(
        description="Cross-source correlations found",
    )
    campaigns_identified: int = Field(
        description="Campaigns identified",
    )
    reasoning: str = Field(
        description="Correlation reasoning",
    )


class EnrichmentOutput(BaseModel):
    """Structured output for indicator enrichment."""

    enriched_count: int = Field(
        description="Indicators enriched with context",
    )
    geo_locations: list[str] = Field(
        description="Top geographic locations",
    )
    reasoning: str = Field(
        description="Enrichment reasoning",
    )


class ThreatScoringOutput(BaseModel):
    """Structured output for threat scoring."""

    critical_count: int = Field(
        description="Critical-level threats",
    )
    actionable_count: int = Field(
        description="Actionable indicators",
    )
    reasoning: str = Field(
        description="Scoring reasoning",
    )


# ── System prompts ────────────────────────────────────

SYSTEM_COLLECT = """\
You are an expert threat intelligence analyst collecting \
data from multiple threat feeds.

Given the fusion configuration and feed sources:
1. Ingest IOCs from STIX/TAXII, OSINT, and commercial feeds
2. Track feed reliability and freshness
3. Identify overlapping coverage and feed gaps
4. Prioritize high-confidence sources

Focus on: feed diversity, timeliness, coverage of \
relevant threat actors and campaigns."""

SYSTEM_NORMALIZE = """\
You are an expert threat intelligence analyst normalizing \
indicators of compromise.

Given the raw IOCs from multiple feeds:
1. Normalize to STIX 2.1 format
2. Deduplicate indicators across sources
3. Standardize IOC types (IP, domain, hash, URL)
4. Tag with source provenance and first-seen dates

Ensure consistency in formatting and preserve \
attribution metadata from original sources."""

SYSTEM_CORRELATE = """\
You are an expert threat intelligence analyst performing \
cross-source correlation.

Given the normalized IOCs:
1. Identify indicators appearing in multiple feeds
2. Cluster related IOCs into campaigns or threat actors
3. Map to MITRE ATT&CK techniques and tactics
4. Detect emerging threat patterns

Higher source overlap increases confidence. \
Focus on campaign attribution and actor tracking."""

SYSTEM_ENRICH = """\
You are an expert threat intelligence analyst enriching \
indicators with context.

Given the correlated indicators:
1. Add geolocation, ASN, and WHOIS data
2. Link to known malware families and campaigns
3. Cross-reference with vulnerability databases
4. Assess historical activity and infrastructure reuse

Contextual enrichment enables better prioritization \
and faster incident response."""

SYSTEM_SCORE = """\
You are an expert threat intelligence analyst scoring \
threat indicators.

Given the enriched and correlated indicators:
1. Score threats on a 0-100 scale based on severity, \
confidence, and relevance
2. Classify threat levels: critical, high, medium, low
3. Determine actionability for blocking or alerting
4. Prioritize by organizational relevance

Balance recency, source reliability, and observed \
activity in scoring methodology."""
