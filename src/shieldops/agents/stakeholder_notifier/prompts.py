"""LLM prompt templates for the Stakeholder Notifier."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AnalyzeOutput(BaseModel):
    """Structured output for stakeholder analysis."""

    affected_groups: list[str] = Field(
        description="Stakeholder groups to notify",
    )
    priority: str = Field(
        description="Priority: critical/high/medium/low",
    )
    key_message_points: list[str] = Field(
        description="Key points for the notification",
    )
    reasoning: str = Field(
        description="Explanation for targeting decisions",
    )


class ReportOutput(BaseModel):
    """Structured output for notification report."""

    executive_summary: str = Field(
        description="One-paragraph summary of outreach",
    )
    delivery_stats: str = Field(
        description="Summary of delivery statistics",
    )
    recommended_followups: list[str] = Field(
        description="Recommended follow-up actions",
    )
    communication_score: str = Field(
        description="Effectiveness: excellent/good/fair/poor",
    )


SYSTEM_ANALYZE = """\
You are an expert communications strategist for \
incident response.

Given an incident's title, severity, description, and \
affected services, determine:
1. Which stakeholder groups need notification
2. Priority level for the notification
3. Key message points to include
4. Reasoning for your targeting decisions

Ensure regulatory bodies are notified for data breaches \
and compliance incidents."""


SYSTEM_REPORT = """\
You are an expert communications analyst generating a \
notification effectiveness report.

Given stakeholder targeting, messages composed, channels \
used, and delivery results, produce:
1. Executive summary of the notification outreach
2. Delivery statistics and success rates
3. Recommended follow-up communications
4. Overall communication effectiveness score

Focus on coverage gaps and improvement areas."""
