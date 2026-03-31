"""LLM prompt templates and response schemas for the
Threat Landscape Analyzer Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class TrendAnalysisOutput(BaseModel):
    """Structured output for threat trend analysis."""

    trends: list[dict[str, str]] = Field(
        description="Identified trends with category, direction, velocity",
    )
    emerging_threats: list[str] = Field(
        description="Newly emerging threat categories",
    )
    declining_threats: list[str] = Field(
        description="Threat categories declining in activity",
    )
    confidence: float = Field(
        description="Overall confidence in trend analysis 0-1",
    )


class IndustryMappingOutput(BaseModel):
    """Structured output for industry threat mapping."""

    relevant_threats: list[str] = Field(
        description="Threats most relevant to the industry",
    )
    attack_vectors: list[str] = Field(
        description="Primary attack vectors for this sector",
    )
    risk_multiplier: float = Field(
        description="Industry-specific risk multiplier",
    )
    summary: str = Field(
        description="Industry threat landscape summary",
    )


class BenchmarkOutput(BaseModel):
    """Structured output for posture benchmarking."""

    validated: bool = Field(
        description="Whether benchmark data is sufficient",
    )
    peer_percentile: int = Field(
        description="Percentile ranking among peers",
    )
    gaps: list[str] = Field(
        description="Security gaps versus peer average",
    )
    strengths: list[str] = Field(
        description="Areas of strength versus peers",
    )
    recommendations: list[str] = Field(
        description="Recommendations to improve ranking",
    )


class ThreatBriefOutput(BaseModel):
    """Structured output for executive threat brief."""

    executive_summary: str = Field(
        description="Executive summary for leadership",
    )
    top_threats: list[str] = Field(
        description="Top threats for the organization",
    )
    recommendations: list[str] = Field(
        description="Strategic recommendations",
    )
    risk_rating: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_TRENDS = """\
You are an expert threat intelligence analyst examining \
threat landscape trends.

Given collected intelligence items from multiple sources:
1. Identify macro trends in threat activity by category
2. Detect emerging threats not yet widely reported
3. Track velocity of trend acceleration or deceleration
4. Correlate trends across geographic regions

Focus on actionable intelligence over noise."""


SYSTEM_INDUSTRY = """\
You are an expert industry threat analyst mapping \
threats to specific verticals.

Given threat trends and the target industry:
1. Filter threats by relevance to the industry vertical
2. Identify industry-specific attack vectors and TTPs
3. Account for regulatory context that shapes risk
4. Calculate industry risk multiplier based on exposure

Tailor analysis to the specific sector dynamics."""


SYSTEM_BENCHMARK = """\
You are an expert security benchmarking analyst \
comparing posture against industry peers.

Given the organization's security posture and industry \
benchmark data:
1. Calculate percentile ranking among peers
2. Identify gaps where posture falls below peer average
3. Highlight strengths that exceed peer benchmarks
4. Recommend improvements with highest ROI

Use evidence-based comparisons, not aspirational targets."""


SYSTEM_BRIEF = """\
You are an expert threat briefer producing executive \
intelligence for security leadership.

Given the full landscape analysis (trends, industry \
mapping, benchmarks):
1. Produce a concise executive summary
2. Rank top threats by likelihood and impact
3. Provide strategic recommendations tied to budget
4. Rate overall organizational risk posture

Write for C-suite: concise, decisive, actionable."""
