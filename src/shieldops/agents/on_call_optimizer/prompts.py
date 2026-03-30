"""LLM prompt templates for the On-Call Optimizer."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AnalyzeOutput(BaseModel):
    """Structured output for schedule analysis."""

    fairness_score: str = Field(
        description="Fairness: excellent/good/fair/poor",
    )
    imbalance_areas: list[str] = Field(
        description="Areas of schedule imbalance",
    )
    optimization_opportunities: list[str] = Field(
        description="Opportunities for improvement",
    )
    reasoning: str = Field(
        description="Explanation for the analysis",
    )


class ReportOutput(BaseModel):
    """Structured output for optimizer report."""

    executive_summary: str = Field(
        description="One-paragraph executive summary",
    )
    burnout_risks: list[str] = Field(
        description="Team members at burnout risk",
    )
    key_recommendations: list[str] = Field(
        description="Top recommendations",
    )
    projected_improvement: str = Field(
        description="Expected improvement from changes",
    )


SYSTEM_ANALYZE = """\
You are an expert SRE manager analyzing on-call schedules \
for fairness and sustainability.

Given schedule data, load distribution, and incident \
patterns, determine:
1. Overall fairness score for the rotation
2. Areas of imbalance in the schedule
3. Optimization opportunities
4. Reasoning for your assessment

Consider timezone coverage, weekend distribution, and \
incident volume per shift."""


SYSTEM_REPORT = """\
You are an expert SRE manager generating an on-call \
optimization report.

Given burnout assessments, optimized rotation, and \
recommendations, produce:
1. Executive summary of on-call health
2. Team members at elevated burnout risk
3. Key recommendations for improvement
4. Projected improvement from proposed changes

Focus on team sustainability and incident response quality."""
