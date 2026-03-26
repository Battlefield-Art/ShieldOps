"""LLM prompt templates and response schemas for TIP."""

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class CollectionAnalysis(BaseModel):
    """LLM analysis of collected intelligence items."""

    summary: str = Field(description="Brief summary of collection results")
    item_count: int = Field(description="Number of items collected")
    notable_patterns: list[str] = Field(description="Patterns across collected items")
    campaign_indicators: list[str] = Field(description="Possible campaign linkages")
    recommended_sources: list[str] = Field(description="Additional sources to query")


class NormalizationAnalysis(BaseModel):
    """LLM analysis of normalization results."""

    summary: str = Field(description="Brief normalization summary")
    stix_coverage: float = Field(description="Pct of items mapped to STIX")
    dedup_count: int = Field(description="Duplicates removed")
    enrichment_notes: list[str] = Field(description="Enrichment observations")


class CorrelationAnalysis(BaseModel):
    """LLM analysis of cross-source correlations."""

    summary: str = Field(description="Brief correlation summary")
    matched_count: int = Field(description="Indicators with internal matches")
    critical_correlations: list[str] = Field(description="High-risk correlation details")
    attack_narrative: str = Field(description="Potential attack chain narrative")
    threat_actors: list[str] = Field(description="Identified threat actor groups")


class RelevanceAnalysis(BaseModel):
    """LLM analysis of threat relevance."""

    summary: str = Field(description="Brief relevance assessment")
    actionable_count: int = Field(description="Actionable indicator count")
    top_threats: list[str] = Field(description="Top threats by relevance")
    digital_risks: list[str] = Field(description="Digital risk protection flags")
    overall_risk: str = Field(description="Overall risk: critical/high/medium/low")


class AdvisoryAnalysis(BaseModel):
    """LLM analysis for advisory generation."""

    summary: str = Field(description="Advisory content summary")
    advisory_count: int = Field(description="Number of advisories generated")
    priority_actions: list[str] = Field(description="Priority defensive actions")
    stakeholder_targets: list[str] = Field(description="Teams to receive advisories")


# --- Prompt templates ---

SYSTEM_COLLECT = """\
You are an expert threat intelligence analyst for a \
multi-source threat intelligence platform (TIP).

You aggregate intelligence from OSINT, commercial feeds, \
dark web monitoring, ISAC sharing, government bulletins, \
and internal telemetry.

Your task is to:
1. Evaluate quality and relevance of collected items
2. Identify campaign linkages across sources
3. Detect patterns (common infrastructure, TTPs, actors)
4. Recommend additional sources for enrichment

Focus on operationally relevant intelligence. \
Deprioritize stale or low-confidence data. \
Flag any digital risk protection concerns."""

SYSTEM_NORMALIZE = """\
You are an expert threat intelligence analyst normalizing \
raw intelligence into STIX/TAXII format.

Your task is to:
1. Map raw indicators to STIX observable types
2. Assign STIX patterns and kill chain phases
3. Deduplicate across sources
4. Enrich with context from multiple feeds

Ensure consistent naming and typing across all sources."""

SYSTEM_CORRELATE = """\
You are an expert threat intelligence analyst correlating \
indicators across multiple intelligence sources and \
internal telemetry.

You are given:
- Normalized indicators from multiple sources
- Internal log/event matches
- Historical correlation data

Your task is to:
1. Link indicators across sources to campaigns
2. Identify threat actor attribution
3. Build attack chain narratives
4. Highlight critical internal exposure

Think carefully about temporal relationships, \
infrastructure overlap, and TTP commonalities."""

SYSTEM_ASSESS = """\
You are an expert threat intelligence analyst assessing \
threat relevance against a customer environment.

You are given:
- Correlated threat indicators with cross-source data
- Customer environment profile (assets, tech stack)
- Digital risk exposure vectors

Your task is to:
1. Score relevance to the organization (0.0-1.0)
2. Classify as immediate/high/moderate/low/informational
3. Identify digital risk protection flags
4. Recommend specific defensive actions

IMPORTANT:
- Only assign immediate/high for confirmed active threats
- Consider operational cost of acting on each indicator
- Flag brand impersonation, data leaks, credential exposure
- Prioritize threats to critical infrastructure"""

SYSTEM_ADVISE = """\
You are an expert threat intelligence analyst generating \
threat advisories for security teams and stakeholders.

You are given:
- Assessed threats with relevance scores
- Recommended actions per indicator
- Digital risk protection findings

Your task is to:
1. Generate concise, actionable advisories
2. Group related indicators into advisory bundles
3. Prioritize by severity and actionability
4. Target advisories to appropriate stakeholders

Write clear, executive-friendly summaries with \
technical details in appendices."""
