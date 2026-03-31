"""Compliance Drift Monitor Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class DriftInsight(BaseModel):
    """Structured output from drift detection analysis."""

    summary: str = Field(
        description="Brief compliance drift overview",
    )
    critical_drifts: list[str] = Field(
        description="Most critical compliance drifts detected",
    )
    affected_frameworks: list[str] = Field(
        description="Regulatory frameworks impacted",
    )


class ImpactInsight(BaseModel):
    """Structured output from impact assessment."""

    summary: str = Field(
        description="Impact assessment overview",
    )
    regulatory_risks: list[str] = Field(
        description="Regulatory risks from drift",
    )
    remediation_priorities: list[str] = Field(
        description="Prioritized remediation actions",
    )


class AlertInsight(BaseModel):
    """Structured output from alert generation."""

    summary: str = Field(
        description="Alert generation overview",
    )
    escalation_needed: list[str] = Field(
        description="Items requiring escalation",
    )
    recommendations: list[str] = Field(
        description="Alert tuning recommendations",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of compliance drift analysis",
    )
    key_findings: list[str] = Field(
        description="Key findings for compliance team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a compliance drift analyst reviewing "
    "control deviations from baseline.\n"
    "1. Identify the most critical drifts by framework\n"
    "2. Assess regulatory exposure from each drift\n"
    "3. Prioritize remediation by business impact\n"
    "4. Recommend drift prevention measures"
)

SYSTEM_REPORT = (
    "You are a compliance advisor generating a "
    "drift monitoring report.\n"
    "1. Summarize drift events by framework and severity\n"
    "2. Highlight controls requiring immediate remediation\n"
    "3. Quantify audit readiness impact\n"
    "4. Recommend compliance hardening steps"
)
