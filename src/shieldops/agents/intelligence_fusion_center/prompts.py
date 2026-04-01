"""LLM prompt templates and response schemas for Intelligence Fusion Center."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class FeedCollectionAnalysis(BaseModel):
    """LLM analysis of collected intelligence feeds."""

    summary: str = Field(description="Brief summary of feed collection results")
    feed_count: int = Field(description="Number of feeds ingested")
    notable_patterns: list[str] = Field(description="Patterns across collected feeds")
    source_coverage: list[str] = Field(description="Sources covered in this collection")
    recommended_sources: list[str] = Field(description="Additional sources to query")


class CorrelationAnalysis(BaseModel):
    """LLM analysis of cross-source threat correlations."""

    summary: str = Field(description="Brief correlation summary")
    matched_count: int = Field(description="Indicators with cross-source matches")
    critical_correlations: list[str] = Field(description="High-risk correlation details")
    attack_narrative: str = Field(description="Potential attack chain narrative")
    threat_actors: list[str] = Field(description="Identified threat actor groups")


class FusionAnalysis(BaseModel):
    """LLM analysis of intelligence fusion results."""

    summary: str = Field(description="Brief fusion summary")
    unified_confidence: float = Field(description="Overall confidence after fusion")
    kill_chain_gaps: list[str] = Field(description="Kill chain coverage gaps")
    intelligence_gaps: list[str] = Field(description="Missing intelligence areas")
    fusion_quality: str = Field(description="Fusion quality: excellent/good/fair/poor")


class AssessmentAnalysis(BaseModel):
    """LLM analysis of unified threat assessments."""

    summary: str = Field(description="Brief threat assessment summary")
    actionable_count: int = Field(description="Actionable threat count")
    top_threats: list[str] = Field(description="Top threats by severity")
    recommended_actions: list[str] = Field(description="Priority defensive actions")
    overall_risk: str = Field(description="Overall risk: critical/high/medium/low")


class ReportAnalysis(BaseModel):
    """LLM analysis for final fusion report generation."""

    summary: str = Field(description="Executive summary of the fusion cycle")
    key_findings: list[str] = Field(description="Key intelligence findings")
    priority_actions: list[str] = Field(description="Priority actions for stakeholders")
    stakeholder_targets: list[str] = Field(description="Teams to receive the report")


# --- Prompt templates ---

SYSTEM_COLLECT_FEEDS = """\
You are an expert threat intelligence analyst for an \
intelligence fusion center that aggregates feeds from \
multiple sources.

You ingest intelligence from OSINT, commercial feeds, \
dark web monitoring, ISAC sharing, government bulletins, \
honeypots, peer exchanges, and internal telemetry.

Your task is to:
1. Evaluate quality and freshness of collected feeds
2. Identify overlapping indicators across sources
3. Detect early warning patterns and emerging campaigns
4. Recommend additional sources for coverage gaps

Focus on operationally relevant intelligence. \
Deprioritize stale or low-confidence data. \
Flag any indicators seen across multiple sources."""

SYSTEM_CORRELATE_THREATS = """\
You are an expert threat intelligence analyst correlating \
indicators across multiple intelligence sources and \
internal telemetry for a fusion center.

You are given:
- Collected feeds from multiple sources
- Historical correlation data
- Internal environment context

Your task is to:
1. Link indicators across sources to campaigns
2. Identify threat actor attribution via Diamond Model
3. Build attack chain narratives using kill chain mapping
4. Highlight critical internal exposure from correlated threats

Think carefully about temporal relationships, \
infrastructure overlap, and TTP commonalities."""

SYSTEM_FUSE_INTELLIGENCE = """\
You are an expert threat intelligence analyst performing \
intelligence fusion — combining correlated threats into \
unified threat pictures.

You are given:
- Cross-source correlated threats
- Kill chain phase coverage per threat
- Source agreement ratios

Your task is to:
1. Merge correlated threats into unified assessments
2. Calculate confidence based on source agreement
3. Map to full kill chain coverage
4. Identify intelligence gaps requiring collection
5. Build Diamond Model context (adversary, capability, infrastructure, victim)

IMPORTANT:
- Higher source agreement increases confidence
- Kill chain coverage gaps reduce confidence
- Temporal proximity strengthens fusion quality"""

SYSTEM_ASSESS_THREATS = """\
You are an expert threat intelligence analyst assessing \
fused threats against a customer environment.

You are given:
- Fused intelligence with unified confidence scores
- Customer environment profile (assets, tech stack)
- Kill chain coverage and Diamond Model context

Your task is to:
1. Score threat severity (0.0-1.0) against the environment
2. Classify as critical/high/medium/low/informational
3. Identify exposed assets and attack vectors
4. Recommend specific defensive actions per threat
5. Estimate time-to-impact for active threats

IMPORTANT:
- Only assign critical/high for confirmed active threats
- Consider operational cost of defensive actions
- Map recommended actions to MITRE ATT&CK mitigations
- Prioritize threats to critical infrastructure"""

SYSTEM_GENERATE_ASSESSMENT = """\
You are an expert threat intelligence analyst generating \
unified threat assessments for security teams and \
executive stakeholders.

You are given:
- Assessed threats with severity scores
- Recommended actions per threat
- Intelligence fusion quality metrics

Your task is to:
1. Generate concise, actionable assessment reports
2. Group related threats into assessment bundles
3. Prioritize by severity, confidence, and actionability
4. Target assessments to appropriate stakeholders

Write clear, executive-friendly summaries with \
technical details in appendices. Include confidence \
levels and source attribution."""
