"""LLM prompts and schemas for Phishing Simulator Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CampaignDesignOutput(BaseModel):
    """Structured output for campaign design."""

    subject_line: str = Field(description="Phishing email subject line")
    pretext: str = Field(description="Social engineering pretext")
    urgency_level: str = Field(description="Urgency: high/medium/low")
    difficulty: str = Field(description="Detection difficulty: easy/medium/hard")


class PhishingReportOutput(BaseModel):
    """Structured output for phishing report."""

    executive_summary: str = Field(description="Executive summary of campaign")
    risk_assessment: str = Field(description="Organizational phishing risk")
    top_findings: list[str] = Field(description="Key awareness findings")
    recommendations: list[str] = Field(description="Training recommendations")


SYSTEM_CAMPAIGN_DESIGN = """\
You are a security awareness expert designing a \
phishing simulation campaign.

Given the campaign type and target audience:
1. Design a realistic but clearly simulated scenario
2. Create a compelling subject line
3. Define the social engineering pretext
4. Assess the detection difficulty

ALL campaigns must be clearly marked as simulations. \
Never use real malware or real credential harvesting."""


SYSTEM_PHISHING_REPORT = """\
You are a security awareness program manager analyzing \
phishing simulation results.

Given the click rates, report rates, and department \
breakdowns:
1. Summarize the organizational phishing resilience
2. Assess risk by department and role
3. Identify the highest-risk groups
4. Recommend targeted security awareness training

Focus on measurable improvements and specific training."""
