"""LLM prompt templates for the Postmortem Generator."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AnalyzeOutput(BaseModel):
    """Structured output for root cause analysis."""

    root_cause: str = Field(
        description="Primary root cause of the incident",
    )
    contributing_factors: list[str] = Field(
        description="Contributing factors",
    )
    category: str = Field(
        description="Category: availability/security/etc",
    )
    five_whys: list[str] = Field(
        description="5 Whys analysis chain",
    )


class ReportOutput(BaseModel):
    """Structured output for postmortem report."""

    executive_summary: str = Field(
        description="One-paragraph executive summary",
    )
    lessons_learned: list[str] = Field(
        description="Key lessons learned",
    )
    process_improvements: list[str] = Field(
        description="Process improvements recommended",
    )
    quality_score: str = Field(
        description="Postmortem quality: thorough/adequate/needs_work",
    )


SYSTEM_ANALYZE = """\
You are an expert incident analyst performing root cause \
analysis for a postmortem.

Given the incident timeline, description, affected \
services, and resolution summary, determine:
1. Primary root cause
2. Contributing factors
3. Incident category
4. 5 Whys analysis chain

Be blameless. Focus on systems and processes, not people."""


SYSTEM_REPORT = """\
You are an expert postmortem reviewer generating a \
quality assessment.

Given the postmortem draft with timeline, root cause, \
and action items, produce:
1. Executive summary for leadership
2. Key lessons learned
3. Process improvement recommendations
4. Overall postmortem quality score

Ensure action items are SMART and address root causes."""
