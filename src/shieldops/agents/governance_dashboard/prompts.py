"""LLM prompt templates and response schemas for Governance Dashboard."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PolicyInsightOutput(BaseModel):
    """Structured output for policy assessment insights."""

    domain_scores: list[dict[str, str]] = Field(
        description="Per-domain adherence summary",
    )
    critical_gaps: list[str] = Field(
        description="Top gaps requiring immediate attention",
    )
    reasoning: str = Field(
        description="Reasoning for the assessment",
    )


class RiskScoringOutput(BaseModel):
    """Structured output for risk scoring."""

    overall_posture: str = Field(
        description="Overall posture: strong/adequate/needs_improvement/weak/critical",
    )
    top_risks: list[str] = Field(
        description="Top risk factors across all domains",
    )
    recommendations: list[str] = Field(
        description="Recommended remediation actions",
    )


class InsightGenerationOutput(BaseModel):
    """Structured output for insight generation."""

    insights: list[str] = Field(
        description="Key governance insights",
    )
    trends: list[str] = Field(
        description="Observed trends in governance posture",
    )
    priority_actions: list[str] = Field(
        description="Priority actions for leadership",
    )


class ExecutiveSummaryOutput(BaseModel):
    """Structured output for executive summary."""

    summary: str = Field(
        description="One-paragraph executive summary",
    )
    posture_label: str = Field(
        description="Overall governance posture label",
    )
    key_metrics: list[str] = Field(
        description="Top 5 key metrics for executives",
    )
    action_items: list[str] = Field(
        description="Recommended executive action items",
    )


SYSTEM_ASSESS_POLICIES = """\
You are an expert governance analyst assessing \
policy adherence across an enterprise.

Given the collected metrics per domain, evaluate:
1. Adherence percentage per policy domain
2. Control gaps that require remediation
3. Framework alignment (SOC 2, ISO 27001, NIST)

Focus on actionable findings, not generic advice."""


SYSTEM_SCORE_RISK = """\
You are an expert risk analyst scoring governance \
risk posture.

Given the policy assessments and metrics:
1. Score each domain from 0-100
2. Determine overall posture (strong/adequate/\
needs_improvement/weak/critical)
3. Identify the top risk factors
4. Recommend specific mitigations

Use evidence from the data, not assumptions."""


SYSTEM_GENERATE_INSIGHTS = """\
You are an expert governance advisor generating \
actionable insights for security leadership.

Given all metrics, assessments, and risk scores:
1. Identify cross-domain trends
2. Highlight improving and degrading areas
3. Prioritize actions by business impact
4. Flag compliance deadlines or audit risks

Be concise and data-driven."""


SYSTEM_EXECUTIVE_SUMMARY = """\
You are an expert executive briefer summarizing \
governance posture for C-suite leadership.

Given the full governance analysis:
1. One-paragraph executive summary
2. Overall posture with justification
3. Top 5 metrics that matter most
4. Recommended actions for leadership

Write for a non-technical executive audience. \
Be direct and outcome-focused."""
