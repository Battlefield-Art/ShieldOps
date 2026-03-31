"""LLM prompt templates and response schemas for the
Dark Web Intelligence Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ForumMonitorOutput(BaseModel):
    """Structured output for forum monitoring."""

    forums: list[dict[str, str]] = Field(
        description="Active forums with name, type, and activity level",
    )
    new_sources: int = Field(
        description="Newly discovered sources",
    )
    coverage_gaps: list[str] = Field(
        description="Threat categories not covered",
    )
    confidence: float = Field(
        description="Monitoring coverage confidence 0-1",
    )


class ThreatAnalysisOutput(BaseModel):
    """Structured output for threat analysis."""

    threats: list[dict[str, str]] = Field(
        description="Analyzed threats with severity and category",
    )
    critical_count: int = Field(
        description="Number of critical threats",
    )
    threat_actors: list[str] = Field(
        description="Identified threat actor aliases",
    )
    summary: str = Field(
        description="Threat landscape summary",
    )


class CredibilityAssessmentOutput(BaseModel):
    """Structured output for credibility assessment."""

    assessments: list[dict[str, str]] = Field(
        description="Credibility ratings per mention",
    )
    verified_count: int = Field(
        description="Number of verified threats",
    )
    disinformation_count: int = Field(
        description="Likely disinformation count",
    )
    confidence: float = Field(
        description="Assessment confidence 0-1",
    )


class DarkWebReportOutput(BaseModel):
    """Structured output for dark web intelligence report."""

    executive_summary: str = Field(
        description="Executive summary of dark web exposure",
    )
    total_mentions: int = Field(
        description="Total mentions found",
    )
    critical_findings: list[str] = Field(
        description="Critical findings requiring action",
    )
    recommendations: list[str] = Field(
        description="Mitigation recommendations",
    )
    risk_level: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_FORUM_MONITOR = """\
You are an expert dark web intelligence analyst \
monitoring underground forums and marketplaces.

Given the organization's profile and keywords:
1. Identify relevant dark web forums and channels
2. Monitor for brand, credential, and data mentions
3. Track threat actor activity and reputation
4. Detect emerging threats before public disclosure

Maintain operational security in all monitoring."""


SYSTEM_THREAT_ANALYSIS = """\
You are an expert cyber threat analyst evaluating \
dark web intelligence for organizational impact.

Given collected dark web mentions:
1. Classify threats by category and severity
2. Identify threat actors and their capabilities
3. Assess potential business impact
4. Correlate with known campaigns and IOCs

Prioritize actionable intelligence over noise."""


SYSTEM_CREDIBILITY = """\
You are an expert intelligence analyst assessing \
source credibility for dark web intelligence.

Given threat mentions and source metadata:
1. Evaluate source reliability and history
2. Cross-reference claims across multiple sources
3. Identify disinformation and scam postings
4. Score credibility using intelligence standards

Err on the side of caution for credential leaks."""


SYSTEM_REPORT = """\
You are an expert threat intelligence reporter \
synthesizing dark web findings for security leaders.

Given the full dark web intelligence collection:
1. Produce an executive summary of exposure
2. Highlight critical, actionable findings
3. Recommend immediate mitigation steps
4. Assess overall dark web risk posture

Write for CISO and incident response teams."""
