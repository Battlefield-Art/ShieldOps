"""LLM prompt templates and response schemas for the
Threat Feed Orchestrator Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class NormalizationOutput(BaseModel):
    """Structured output for indicator normalization."""

    normalized_count: int = Field(
        description="Number of indicators normalized",
    )
    format_issues: list[str] = Field(
        description="Format parsing issues encountered",
    )
    type_distribution: dict[str, int] = Field(
        description="Count per indicator type",
    )
    quality_score: float = Field(
        description="Overall data quality score 0-1",
    )


class DeduplicationOutput(BaseModel):
    """Structured output for indicator deduplication."""

    unique_count: int = Field(
        description="Number of unique indicators",
    )
    duplicate_count: int = Field(
        description="Number of duplicates removed",
    )
    merge_decisions: list[str] = Field(
        description="Notable merge/dedup decisions",
    )
    dedup_ratio: float = Field(
        description="Deduplication ratio (removed/total)",
    )


class EnrichmentOutput(BaseModel):
    """Structured output for indicator enrichment."""

    enriched_count: int = Field(
        description="Number of indicators enriched",
    )
    threat_actors: list[str] = Field(
        description="Threat actors identified",
    )
    campaigns: list[str] = Field(
        description="Active campaigns detected",
    )
    avg_risk_score: float = Field(
        description="Average risk score of enriched IOCs",
    )


class PipelineReportOutput(BaseModel):
    """Structured output for final pipeline report."""

    executive_summary: str = Field(
        description="Executive summary of feed pipeline run",
    )
    feed_health: list[dict[str, str]] = Field(
        description="Health status per feed source",
    )
    top_threats: list[str] = Field(
        description="Top threat indicators to prioritize",
    )
    recommendations: list[str] = Field(
        description="Feed management recommendations",
    )
    effectiveness_rating: str = Field(
        description="Pipeline effectiveness: high/medium/low",
    )


# --- System prompts ---


SYSTEM_NORMALIZE = """\
You are an expert threat intelligence analyst normalizing \
indicators from multiple feed formats.

Given raw indicators from STIX/TAXII, CSV, JSON, and \
MISP feeds:
1. Normalize to a common STIX 2.1 schema
2. Classify indicator types (IP, domain, hash, URL, etc.)
3. Assess data quality and flag parsing issues
4. Preserve provenance and confidence metadata

Accuracy of normalization is critical for downstream \
correlation."""


SYSTEM_DEDUP = """\
You are an expert threat intelligence analyst \
deduplicating indicators across feeds.

Given normalized indicators from multiple sources:
1. Identify exact and fuzzy duplicates across feeds
2. Merge confidence scores from multiple sources
3. Preserve the highest-fidelity version of each IOC
4. Track provenance across merged indicators

Err toward keeping indicators when dedup is ambiguous."""


SYSTEM_ENRICH = """\
You are an expert threat intelligence analyst enriching \
indicators with contextual data.

Given deduplicated indicators and enrichment sources:
1. Map indicators to threat actors and campaigns
2. Assign MITRE ATT&CK technique mappings
3. Score risk based on recency, source confidence, \
and context
4. Add geolocation and infrastructure relationships

Prioritize enrichment for high-confidence, recent IOCs."""


SYSTEM_REPORT = """\
You are an expert threat intelligence manager generating \
a feed pipeline report.

Given the full pipeline run (connections, normalization, \
dedup, enrichment, distribution):
1. Summarize feed health and data quality
2. Highlight top threat indicators for analyst attention
3. Recommend feed management actions (add, remove, tune)
4. Rate overall pipeline effectiveness

Write for both SOC analysts and threat intel leadership."""
