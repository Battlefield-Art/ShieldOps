"""LLM prompt templates and response schemas for the
Security Lake Manager Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class SourceDiscoveryOutput(BaseModel):
    """Structured output for data source discovery."""

    sources: list[dict[str, str]] = Field(
        description="Discovered sources with name, type, and format",
    )
    total_volume_gb: float = Field(
        description="Estimated daily volume in GB",
    )
    coverage_gaps: list[str] = Field(
        description="Missing security data categories",
    )
    confidence: float = Field(
        description="Discovery completeness confidence 0-1",
    )


class SchemaNormalizationOutput(BaseModel):
    """Structured output for schema normalization."""

    mappings: list[dict[str, str]] = Field(
        description="Field mappings from source to OCSF",
    )
    unmapped_fields: list[str] = Field(
        description="Fields that could not be mapped",
    )
    normalization_rate: float = Field(
        description="Percentage of fields successfully mapped",
    )
    summary: str = Field(
        description="Normalization summary",
    )


class StorageOptimizationOutput(BaseModel):
    """Structured output for storage optimization."""

    recommendations: list[dict[str, str]] = Field(
        description="Tiering recommendations with partition and savings",
    )
    total_savings_pct: float = Field(
        description="Overall cost savings percentage",
    )
    hot_to_warm_candidates: int = Field(
        description="Partitions to move from hot to warm",
    )
    summary: str = Field(
        description="Optimization summary",
    )


class LakeReportOutput(BaseModel):
    """Structured output for security lake report."""

    executive_summary: str = Field(
        description="Executive summary of lake health",
    )
    total_sources: int = Field(
        description="Total active data sources",
    )
    daily_volume_gb: float = Field(
        description="Daily ingestion volume in GB",
    )
    recommendations: list[str] = Field(
        description="Operational recommendations",
    )
    health_score: str = Field(
        description="Lake health: excellent/good/fair/poor",
    )


# --- System prompts ---


SYSTEM_SOURCE_DISCOVERY = """\
You are an expert security data lake architect \
discovering data sources.

Given the environment inventory and connectors:
1. Identify all security-relevant data sources
2. Classify source types (EDR, SIEM, cloud, network)
3. Estimate daily volume and event sizes
4. Identify coverage gaps in security telemetry

Prioritize sources with high detection value."""


SYSTEM_SCHEMA_NORMALIZATION = """\
You are an expert security data engineer normalizing \
schemas to OCSF format.

Given raw event schemas from multiple sources:
1. Map fields to OCSF categories and attributes
2. Identify semantic equivalences across vendors
3. Flag unmappable proprietary fields
4. Recommend enrichment for sparse schemas

Maintain fidelity — never drop security-critical \
fields."""


SYSTEM_STORAGE_OPTIMIZATION = """\
You are an expert data lake cost optimizer managing \
tiered storage for security data.

Given ingestion patterns and query frequencies:
1. Recommend hot/warm/cold/archive tiering
2. Estimate cost savings per partition move
3. Ensure compliance retention requirements are met
4. Optimize for query performance on hot data

Balance cost savings with investigation readiness."""


SYSTEM_REPORT = """\
You are an expert security data lake operator \
generating operational reports.

Given lake metrics (sources, volumes, costs, queries):
1. Produce a health summary for the security team
2. Highlight ingestion anomalies and gaps
3. Report on normalization completeness
4. Recommend operational improvements

Write for both data engineering and security \
audiences."""
