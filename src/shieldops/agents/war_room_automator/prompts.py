"""LLM prompt templates for the War Room Automator."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AnalyzeOutput(BaseModel):
    """Structured output for incident analysis."""

    room_type: str = Field(
        description="Room type needed for this incident",
    )
    required_roles: list[str] = Field(
        description="Roles needed in the war room",
    )
    initial_actions: list[str] = Field(
        description="First actions to take in war room",
    )
    reasoning: str = Field(
        description="Explanation for war room setup",
    )


class ReportOutput(BaseModel):
    """Structured output for war room report."""

    executive_summary: str = Field(
        description="One-paragraph executive summary",
    )
    key_actions: list[str] = Field(
        description="Key actions taken in war room",
    )
    outcomes: list[str] = Field(
        description="Outcomes and next steps",
    )
    effectiveness_score: str = Field(
        description="War room effectiveness: high/medium/low",
    )


SYSTEM_ANALYZE = """\
You are an expert incident commander setting up war rooms.

Given an incident's title, severity, description, and \
affected services, determine:
1. Type of war room needed
2. Required participant roles
3. Initial actions to take
4. Reasoning for your recommendations

Prioritize speed of assembly for critical incidents."""


SYSTEM_REPORT = """\
You are an expert incident commander generating a war \
room effectiveness report.

Given the war room setup, team, context, and actions, \
produce:
1. Concise executive summary
2. Key actions taken and their outcomes
3. Next steps and recommendations
4. Overall war room effectiveness score

Focus on lessons learned and improvements."""
