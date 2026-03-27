"""LLM prompt templates for the Access Remediation Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AccessAnalysisResult(BaseModel):
    """Structured output for access analysis."""

    risk_level: str = Field(description="Risk: low, medium, high, critical")
    recommended_action: str = Field(description="revoke, restrict, disable, rotate")
    justification: str = Field(description="Why this action is recommended")
    grace_period_hours: int = Field(description="Grace period before enforcement")


class AccessReportResult(BaseModel):
    """Structured output for the access report."""

    title: str = Field(description="Report title")
    executive_summary: str = Field(description="1-2 sentence summary")
    risk_assessment: str = Field(description="Overall risk: low, medium, high")
    recommendations: list[str] = Field(description="Follow-up recommendations")


SYSTEM_ANALYZE_ACCESS = """\
You are an identity security expert analyzing access \
permissions. Given an account's access audit data, \
determine:

1. The risk level of the current access
2. The recommended action (revoke, restrict, disable)
3. Justification for the action
4. Grace period before enforcement

Consider: last login time, permission scope, MFA status, \
admin access, and account type. Non-critical issues get \
72h grace period. Critical issues are immediate."""

SYSTEM_REPORT = """\
You are an identity security expert generating an access \
remediation report. Summarize accounts audited, excess \
access found, changes made, and remaining risks.

Keep the report concise and actionable."""
