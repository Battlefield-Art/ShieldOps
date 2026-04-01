"""LLM prompt templates for the Threat Actor Profiler Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class IndicatorCollectionOutput(BaseModel):
    """Structured output for indicator collection."""

    total_indicators: int = Field(description="Total indicators collected")
    high_confidence: int = Field(description="High-confidence indicators")
    summary: str = Field(description="Collection summary")


class ClusteringOutput(BaseModel):
    """Structured output for activity clustering."""

    total_clusters: int = Field(description="Total activity clusters")
    avg_similarity: float = Field(description="Average cluster similarity score")
    reasoning: str = Field(description="Clustering reasoning")


class ProfileBuildOutput(BaseModel):
    """Structured output for profile building."""

    profiles_built: int = Field(description="Profiles constructed")
    apt_count: int = Field(description="APT actors identified")
    reasoning: str = Field(description="Profiling reasoning")


class TTPMappingOutput(BaseModel):
    """Structured output for TTP mapping."""

    techniques_mapped: int = Field(description="MITRE techniques mapped")
    tactics_covered: int = Field(description="Tactics covered")
    reasoning: str = Field(description="TTP mapping reasoning")


class TargetingOutput(BaseModel):
    """Structured output for targeting assessment."""

    actors_assessed: int = Field(description="Actors assessed for targeting")
    high_risk_count: int = Field(description="High-risk actors to org")
    reasoning: str = Field(description="Targeting reasoning")


# ── System prompts ────────────────────────────────────

SYSTEM_COLLECT_INDICATORS = """\
You are an expert threat intelligence analyst collecting \
indicators of compromise.

Given the intelligence sources:
1. Gather IOCs from threat feeds and internal telemetry
2. Validate indicator quality and freshness
3. Deduplicate across sources
4. Assign initial confidence levels

Focus on: IP addresses, domains, file hashes, TTPs, \
behavioral patterns."""

SYSTEM_CLUSTER_ACTIVITY = """\
You are an expert threat intelligence analyst clustering \
related activity.

Given collected indicators:
1. Group indicators by shared characteristics
2. Identify temporal and behavioral patterns
3. Calculate similarity scores between clusters
4. Link clusters to known campaigns when possible

Use: diamond model, kill chain alignment, temporal analysis."""

SYSTEM_BUILD_PROFILES = """\
You are an expert threat intelligence analyst building \
actor profiles.

Given activity clusters:
1. Construct actor profiles from cluster patterns
2. Classify actor type (APT, criminal, hacktivist, etc.)
3. Assess capability level and resources
4. Identify motivation and objectives

Reference: known threat actor databases, MITRE groups."""

SYSTEM_MAP_TTPS = """\
You are an expert threat intelligence analyst mapping TTPs \
to MITRE ATT&CK.

Given actor profiles:
1. Map observed behaviors to ATT&CK techniques
2. Identify tactic coverage across the kill chain
3. Assess technique frequency and sophistication
4. Compare with known actor TTP fingerprints

Use MITRE ATT&CK Enterprise framework v14+."""

SYSTEM_ASSESS_TARGETING = """\
You are an expert threat intelligence analyst assessing \
targeting patterns.

Given actor profiles and TTP mappings:
1. Identify targeted industry sectors
2. Map geographic targeting preferences
3. Assess risk to the organization specifically
4. Generate defensive recommendations

Focus on: sector relevance, geographic overlap, \
capability vs. defenses."""
