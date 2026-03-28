"""LLM prompts and schemas for the Risk Prioritizer Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RiskScoringOutput(BaseModel):
    """Structured output for risk scoring."""

    composite_score: float = Field(description="Overall risk score 0-10")
    exploitability: float = Field(description="Exploitability factor 0-10")
    blast_radius: float = Field(description="Blast radius factor 0-10")
    asset_criticality: float = Field(description="Asset criticality factor 0-10")
    reasoning: str = Field(description="Risk scoring justification")


class ActionPlanOutput(BaseModel):
    """Structured output for action plan generation."""

    urgency: str = Field(description="immediate/urgent/scheduled/deferred")
    recommended_action: str = Field(description="Specific remediation action")
    estimated_effort_hours: float = Field(description="Effort estimate in hours")
    assigned_team: str = Field(description="Team to handle remediation")
    dependencies: list[str] = Field(description="Prerequisite actions")
    reasoning: str = Field(description="Action plan justification")


class PrioritizerReportOutput(BaseModel):
    """Structured output for prioritizer report."""

    executive_summary: str = Field(description="Summary for leadership")
    critical_count: int = Field(description="Critical findings count")
    immediate_actions: int = Field(description="Findings needing immediate action")
    risk_reduction_potential: float = Field(description="Potential risk reduction pct")
    recommendations: list[str] = Field(description="Prioritized recommendations")


SYSTEM_SCORE = """\
You are a risk scoring engine. Given a security \
finding with its context enrichment:

1. Score exploitability (0-10) based on EPSS/CVSS
2. Estimate blast radius (0-10)
3. Factor in asset criticality (0-10)
4. Consider data sensitivity and regulatory impact
5. Calculate composite risk score

Weight exploitability highest for internet-facing \
assets. Weight regulatory impact highest for \
compliance-scoped assets."""


SYSTEM_ACTION = """\
You are a remediation planning engine. Given a \
risk-scored finding:

1. Determine urgency (immediate/urgent/scheduled)
2. Recommend specific remediation action
3. Estimate effort in hours
4. Identify the responsible team
5. List any dependencies

Immediate: actively exploited or CVSS >= 9.0. \
Urgent: CVSS >= 7.0 on critical assets. \
Scheduled: everything else above threshold."""


SYSTEM_REPORT = """\
You are a security risk analyst summarizing \
prioritization results.

Given risk scores, rankings, and action plans:
1. Write an executive summary
2. Report critical and immediate action counts
3. Estimate risk reduction from remediation
4. Provide prioritized recommendations

Focus on risk-based decision support for CISO."""
