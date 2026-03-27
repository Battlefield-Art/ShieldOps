"""Executive Reporter Agent — LLM prompt templates."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TrendNarrativeOutput(BaseModel):
    """LLM output for trend narrative generation."""

    narratives: list[str] = Field(
        description="Trend narratives per metric",
    )
    overall_direction: str = Field(
        description="Overall posture direction",
    )
    areas_of_concern: list[str] = Field(
        description="Areas trending negatively",
    )


class FindingSummaryOutput(BaseModel):
    """LLM output for finding summarization."""

    title: str = Field(
        description="Concise finding title",
    )
    executive_description: str = Field(
        description="Board-level description",
    )
    business_impact: str = Field(
        description="Business impact statement",
    )
    severity: str = Field(
        description="Severity: critical/high/medium/low",
    )


class RecommendationOutput(BaseModel):
    """LLM output for recommendation generation."""

    title: str = Field(
        description="Recommendation title",
    )
    rationale: str = Field(
        description="Why this matters",
    )
    estimated_impact: str = Field(
        description="Expected security improvement",
    )
    timeline: str = Field(
        description="Suggested timeline",
    )
    priority: str = Field(
        description="Priority: critical/high/medium/low",
    )


class ReportCompositionOutput(BaseModel):
    """LLM output for full report composition."""

    executive_summary: str = Field(
        description="Executive summary paragraph",
    )
    posture_narrative: str = Field(
        description="Security posture narrative",
    )
    threat_landscape: str = Field(
        description="Threat landscape summary",
    )
    key_takeaways: list[str] = Field(
        description="Key takeaways for leadership",
    )


SYSTEM_COLLECT_METRICS = (
    "You are a security metrics analyst collecting "
    "KPIs from across the security program.\n"
    "Collect metrics for:\n"
    "1. Security posture score and domain scores\n"
    "2. Incident volume, MTTD, MTTR\n"
    "3. Vulnerability counts and remediation rates\n"
    "4. Compliance coverage percentages"
)

SYSTEM_ANALYZE_TRENDS = (
    "You are a security analyst writing trend "
    "narratives for executive consumption.\n"
    "For each metric:\n"
    "1. Describe the trend direction clearly\n"
    "2. Explain what drove the change\n"
    "3. Indicate whether this is concerning\n"
    "4. Use plain language, avoid jargon"
)

SYSTEM_SUMMARIZE_FINDINGS = (
    "You are a CISO advisor summarizing security "
    "findings for a board-level audience.\n"
    "For each finding:\n"
    "1. Write a concise, non-technical title\n"
    "2. Describe business impact\n"
    "3. Indicate severity\n"
    "4. Recommend next steps"
)

SYSTEM_GENERATE_RECOMMENDATIONS = (
    "You are a security strategy advisor generating "
    "recommendations for the executive team.\n"
    "For each recommendation:\n"
    "1. Clearly state what to do and why\n"
    "2. Quantify expected security improvement\n"
    "3. Estimate timeline and effort\n"
    "4. Assign priority"
)

SYSTEM_COMPOSE_REPORT = (
    "You are a CISO writing a polished executive "
    "security report.\n"
    "The report must:\n"
    "1. Lead with a crisp executive summary\n"
    "2. Present data-driven posture assessment\n"
    "3. Highlight top risks and findings\n"
    "4. Close with prioritized recommendations\n"
    "Use clear, non-technical language. "
    "Focus on business risk and outcomes."
)
