"""LLM prompt templates and response schemas for the SLA Monitor Agent."""

from pydantic import BaseModel, Field


class BurnRateAnalysisOutput(BaseModel):
    """Structured output for burn rate analysis."""

    severity: str = Field(description="Overall severity: critical/high/warning/info")
    root_cause_hypothesis: str = Field(description="Likely root cause of budget burn")
    recommended_actions: list[str] = Field(description="Ordered list of recommended actions")
    estimated_impact: str = Field(description="Estimated impact if no action is taken")
    confidence: float = Field(description="Confidence in the analysis 0-1")


class SLAReportOutput(BaseModel):
    """Structured output for SLA report generation."""

    executive_summary: str = Field(description="1-2 sentence executive summary")
    services_at_risk: list[str] = Field(description="Services at risk of SLA breach")
    key_findings: list[str] = Field(description="Key findings from the monitoring cycle")
    recommendations: list[str] = Field(description="Prioritized recommendations")


SYSTEM_BURN_RATE = """\
You are an expert SRE analyzing error budget burn rates.

Given the SLO statuses and burn rate data:
1. Assess overall severity considering multi-window burn rates
2. Hypothesize the likely root cause based on patterns
3. Recommend specific, prioritized actions
4. Estimate the impact if no action is taken

Use Google SRE burn rate methodology (1h and 6h windows)."""


SYSTEM_REPORT = """\
You are an expert SRE generating an SLA monitoring report.

Given the collected SLI metrics, SLO statuses, and error budget data:
1. Provide a concise executive summary
2. Identify services at risk of SLA breach
3. Highlight key findings and trends
4. Recommend prioritized actions

Focus on actionable insights, not raw data."""


SYSTEM_ALERT = """\
You are an expert SRE crafting alert notifications.

Given burn rate alert data, compose clear and actionable alert content:
1. State the issue concisely
2. Include relevant metrics (burn rate, time to exhaustion)
3. Recommend immediate action
4. Specify escalation path if not resolved

Follow PagerDuty best practices for alert content."""
