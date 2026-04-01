"""LLM prompt templates for the Security Telemetry Aggregator."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -------------------------------


class TelemetryCollectionOutput(BaseModel):
    """Structured output for telemetry collection."""

    total_collected: int = Field(
        description="Total telemetry records collected",
    )
    source_breakdown: dict[str, int] = Field(
        description="Count per source",
    )
    summary: str = Field(description="Collection summary")


class NormalizationOutput(BaseModel):
    """Structured output for signal normalization."""

    normalized_count: int = Field(
        description="Signals normalized",
    )
    dropped_count: int = Field(
        description="Signals dropped during normalization",
    )
    reasoning: str = Field(description="Normalization reasoning")


class CorrelationOutput(BaseModel):
    """Structured output for event correlation."""

    clusters_found: int = Field(
        description="Correlated clusters found",
    )
    avg_correlation: float = Field(
        description="Average correlation score",
    )
    reasoning: str = Field(description="Correlation reasoning")


class EnrichmentOutput(BaseModel):
    """Structured output for context enrichment."""

    enriched_count: int = Field(
        description="Events enriched",
    )
    avg_risk_score: float = Field(
        description="Average risk score",
    )
    reasoning: str = Field(description="Enrichment reasoning")


class AlertRoutingOutput(BaseModel):
    """Structured output for alert routing."""

    alerts_routed: int = Field(
        description="Alerts routed",
    )
    critical_alerts: int = Field(
        description="Critical priority alerts",
    )
    reasoning: str = Field(description="Routing reasoning")


# -- System prompts ------------------------------------------

SYSTEM_COLLECT = """\
You are an expert security telemetry analyst collecting \
telemetry from agents and connectors.

Given the telemetry configuration:
1. Collect records from all configured sources
2. Validate record format and completeness
3. Deduplicate records from overlapping sources
4. Track collection coverage per source

Focus on: completeness, source diversity, freshness."""

SYSTEM_NORMALIZE = """\
You are an expert security analyst normalizing telemetry \
signals to a common schema.

Given raw telemetry records:
1. Map vendor-specific fields to OCSF schema
2. Normalize severity and priority values
3. Standardize timestamps to UTC
4. Flag records that cannot be normalized

Prioritize data fidelity over speed."""

SYSTEM_CORRELATE = """\
You are an expert security analyst correlating events \
across telemetry sources.

Given normalized signals:
1. Identify related signals by temporal proximity
2. Cluster signals by shared indicators (IP, hash, user)
3. Score correlation confidence per cluster
4. Identify attack chain patterns

Focus on: minimizing false correlations."""

SYSTEM_ENRICH = """\
You are an expert threat intelligence analyst enriching \
correlated events with context.

Given correlated event clusters:
1. Lookup threat intelligence for indicators
2. Resolve asset ownership and criticality
3. Calculate composite risk scores
4. Add geolocation and reputation data

Use multiple enrichment sources for accuracy."""

SYSTEM_ROUTE = """\
You are an expert SOC analyst routing alerts to the \
appropriate response teams.

Given enriched events:
1. Match alert priority to response SLA
2. Route to specialized teams by event type
3. Ensure critical alerts reach multiple channels
4. Track routing acknowledgment

Optimize for: fastest triage, zero missed criticals."""
