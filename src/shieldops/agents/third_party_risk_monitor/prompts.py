"""LLM prompt templates and response schemas for the
Third Party Risk Monitor Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class VendorInventoryOutput(BaseModel):
    """Structured output for vendor inventory analysis."""

    total_vendors: int = Field(
        description="Total vendors inventoried",
    )
    critical_vendors: list[str] = Field(
        description="Vendors classified as critical tier",
    )
    data_risk_vendors: list[str] = Field(
        description="Vendors with sensitive data access",
    )
    summary: str = Field(
        description="Inventory summary",
    )


class PostureAssessmentOutput(BaseModel):
    """Structured output for posture assessment."""

    vendors_assessed: int = Field(
        description="Number of vendors assessed",
    )
    weak_posture: list[str] = Field(
        description="Vendors with weak security posture",
    )
    avg_score: float = Field(
        description="Average posture score 0-100",
    )
    gaps: list[str] = Field(
        description="Common security gaps found",
    )


class RiskEvaluationOutput(BaseModel):
    """Structured output for risk evaluation."""

    high_risk_count: int = Field(
        description="Number of high-risk vendors",
    )
    risk_factors: list[str] = Field(
        description="Top risk factors identified",
    )
    recommendations: list[str] = Field(
        description="Risk mitigation recommendations",
    )
    overall_exposure: str = Field(
        description="Overall third-party risk exposure",
    )


class RiskReportOutput(BaseModel):
    """Structured output for risk monitoring report."""

    executive_summary: str = Field(
        description="Executive summary for leadership",
    )
    high_risk_vendors: int = Field(
        description="Count of high-risk vendors",
    )
    alerts_generated: int = Field(
        description="Alerts raised during monitoring",
    )
    recommendations: list[str] = Field(
        description="Prioritized action items",
    )
    trend: str = Field(
        description="Risk trend: improving/stable/worsening",
    )


# --- System prompts ---


SYSTEM_INVENTORY = """\
You are an expert third-party risk analyst inventorying \
vendor relationships for risk monitoring.

Given the vendor filters and organization context:
1. Classify vendors by criticality tier based on data \
access and service dependency
2. Identify vendors with access to sensitive or regulated data
3. Flag vendors with expired certifications or assessments
4. Highlight concentration risk in single-vendor dependencies

Focus on supply chain risk and data exposure."""


SYSTEM_ASSESS = """\
You are an expert vendor security assessor evaluating \
third-party security posture.

Given vendor profiles and assessment data:
1. Score each vendor across security, compliance, and \
operational risk domains
2. Identify certification gaps (SOC 2, ISO 27001, etc.)
3. Assess data handling practices and encryption standards
4. Flag vendors failing SLA or incident response requirements

Be thorough — vendor breaches cascade to customers."""


SYSTEM_EVALUATE = """\
You are an expert risk evaluator analyzing third-party \
vendor risk across multiple domains.

Given posture assessments and change monitoring data:
1. Calculate composite risk scores per vendor
2. Identify emerging risk trends and posture degradation
3. Map vendor risks to business impact
4. Recommend risk mitigation or vendor replacement

Prioritize vendors with access to crown jewel data."""


SYSTEM_REPORT = """\
You are an expert third-party risk reporter synthesizing \
continuous monitoring results.

Given all assessments, changes, risk evaluations, and alerts:
1. Produce an executive summary for risk leadership
2. Highlight vendors requiring immediate attention
3. Summarize risk trends over the monitoring period
4. Recommend vendor governance program improvements

Write for both security and procurement audiences."""
