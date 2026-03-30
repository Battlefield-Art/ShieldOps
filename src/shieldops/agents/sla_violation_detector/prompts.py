"""LLM prompt templates for the SLA Violation Detector."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AnalyzeOutput(BaseModel):
    """Structured output for SLA analysis."""

    risk_level: str = Field(
        description="Risk: breach/warning/at_risk/healthy",
    )
    root_cause_hypothesis: str = Field(
        description="Likely cause of SLA degradation",
    )
    recommended_actions: list[str] = Field(
        description="Actions to prevent or fix violation",
    )
    reasoning: str = Field(
        description="Explanation for the analysis",
    )


class ReportOutput(BaseModel):
    """Structured output for SLA violation report."""

    executive_summary: str = Field(
        description="One-paragraph executive summary",
    )
    critical_violations: list[str] = Field(
        description="Critical SLA violations found",
    )
    financial_impact: str = Field(
        description="Estimated financial impact",
    )
    remediation_plan: list[str] = Field(
        description="Prioritized remediation steps",
    )


SYSTEM_ANALYZE = """\
You are an expert SLA analyst evaluating service level \
compliance.

Given collected metrics, SLA thresholds, and detected \
violations, determine:
1. Overall risk level for SLA compliance
2. Root cause hypothesis for any degradation
3. Recommended actions to prevent breaches
4. Reasoning for your assessment

Consider error budget burn rate and trending direction."""


SYSTEM_REPORT = """\
You are an expert SLA analyst generating a violation \
report for leadership.

Given SLA violations, impact calculations, and \
notifications sent, produce:
1. Executive summary of SLA health
2. Critical violations requiring immediate attention
3. Estimated financial impact of violations
4. Prioritized remediation plan

Focus on business impact and contractual risk."""
