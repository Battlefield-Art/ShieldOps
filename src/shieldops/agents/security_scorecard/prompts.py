"""Security Scorecard Agent — LLM prompt templates."""

from __future__ import annotations

from pydantic import BaseModel, Field


class InsightGenerationOutput(BaseModel):
    """LLM output for security insight generation."""

    insights: list[str] = Field(
        description="Key security insights from scores",
    )
    risk_areas: list[str] = Field(
        description="Areas of highest risk",
    )
    quick_wins: list[str] = Field(
        description="Quick wins for score improvement",
    )
    strategic_recommendations: list[str] = Field(
        description="Strategic recommendations",
    )


class TrendAnalysisOutput(BaseModel):
    """LLM output for trend analysis."""

    trend_summary: str = Field(
        description="Summary of security posture trend",
    )
    improving_areas: list[str] = Field(
        description="Areas showing improvement",
    )
    degrading_areas: list[str] = Field(
        description="Areas showing degradation",
    )


class ScorecardReportOutput(BaseModel):
    """LLM output for scorecard report."""

    executive_summary: str = Field(
        description="Board-level executive summary",
    )
    key_metrics: list[str] = Field(
        description="Key metrics to highlight",
    )
    action_items: list[str] = Field(
        description="Prioritized action items",
    )


SYSTEM_COLLECT_SCORES = (
    "You are a security posture analyst collecting "
    "domain scores across the organization.\n"
    "For each security domain:\n"
    "1. Assess the current maturity level\n"
    "2. Count critical issues and findings\n"
    "3. Assign a score from 0-100\n"
    "4. Identify the most impactful improvement"
)

SYSTEM_GENERATE_INSIGHTS = (
    "You are a CISO advisor generating security "
    "insights from posture scores.\n"
    "Given domain scores and trends:\n"
    "1. Identify the highest-risk areas\n"
    "2. Find quick wins for score improvement\n"
    "3. Provide strategic recommendations\n"
    "4. Highlight areas needing investment"
)

SYSTEM_ANALYZE_TRENDS = (
    "You are a security metrics analyst tracking "
    "posture trends over 30/60/90 day windows.\n"
    "For the trend data:\n"
    "1. Identify improving vs degrading areas\n"
    "2. Correlate changes with events\n"
    "3. Forecast near-term trajectory\n"
    "4. Flag concerning trend reversals"
)

SYSTEM_REPORT = (
    "You are a CISO writing a board-level security "
    "posture report.\n"
    "Produce an executive summary covering:\n"
    "1. Overall security grade and score\n"
    "2. Domain-level breakdown\n"
    "3. Trend direction and velocity\n"
    "4. Top 3 action items with expected impact"
)
