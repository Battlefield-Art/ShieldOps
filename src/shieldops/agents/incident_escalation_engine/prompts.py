"""LLM prompt templates for the Incident Escalation Engine."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AnalyzeOutput(BaseModel):
    """Structured output for severity analysis."""

    urgency: str = Field(
        description="Urgency: immediate/urgent/high/medium/low",
    )
    blast_radius: str = Field(
        description="Estimated blast radius description",
    )
    escalation_tier: str = Field(
        description="Recommended tier: tier_1-3/executive",
    )
    reasoning: str = Field(
        description="Explanation for the assessment",
    )


class ReportOutput(BaseModel):
    """Structured output for escalation report."""

    executive_summary: str = Field(
        description="One-paragraph executive summary",
    )
    key_decisions: list[str] = Field(
        description="Key escalation decisions made",
    )
    recommended_actions: list[str] = Field(
        description="Prioritized next actions",
    )
    risk_level: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


SYSTEM_ANALYZE = """\
You are an expert incident escalation analyst.

Given an incident's title, description, severity, \
affected services, and alert count, determine:
1. Urgency level (immediate, urgent, high, medium, low)
2. Blast radius and customer impact
3. Recommended escalation tier
4. Reasoning for your assessment

Err on the side of higher urgency when uncertain."""


SYSTEM_REPORT = """\
You are an expert incident commander generating a report.

Given escalation decisions, notifications, and response \
tracking, produce:
1. Concise executive summary for leadership
2. Key escalation decisions and their rationale
3. Prioritized recommended actions
4. Overall risk assessment

Be direct and actionable."""
