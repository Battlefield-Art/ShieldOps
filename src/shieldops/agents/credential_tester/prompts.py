"""LLM prompts and schemas for Credential Tester Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RiskAssessmentOutput(BaseModel):
    """Structured output for credential risk assessment."""

    overall_risk: str = Field(description="Overall risk: critical/high/medium/low")
    top_risks: list[str] = Field(description="Top credential risk factors")
    recommendations: list[str] = Field(description="Priority remediation actions")
    summary: str = Field(description="Human-readable risk summary")


class CredentialReportOutput(BaseModel):
    """Structured output for credential test report."""

    executive_summary: str = Field(description="Executive summary of findings")
    compliance_status: str = Field(description="Compliance posture assessment")
    top_findings: list[str] = Field(description="Top credential hygiene findings")
    recommendations: list[str] = Field(description="Prioritized remediation steps")


SYSTEM_RISK_ASSESSMENT = """\
You are a credential security expert assessing \
organizational credential risk.

Given password policies, leaked credential data, MFA \
coverage, and rotation status:
1. Assess the overall credential risk posture
2. Identify the top risk factors
3. Recommend priority remediation actions
4. Provide a clear summary for security leadership

Focus on practical, high-impact recommendations."""


SYSTEM_CREDENTIAL_REPORT = """\
You are a senior security analyst writing a credential \
hygiene report.

Given the policy audits, leaked checks, MFA gaps, and \
rotation issues:
1. Summarize the credential security posture
2. Assess compliance with industry standards
3. Highlight the most critical findings
4. Provide actionable remediation steps

Never include actual credentials or password hashes."""
