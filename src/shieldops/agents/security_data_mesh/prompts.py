"""Security Data Mesh Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class DomainInsight(BaseModel):
    """Structured output from domain discovery analysis."""

    summary: str = Field(
        description="Brief data mesh overview",
    )
    gaps: list[str] = Field(
        description="Detected coverage gaps across domains",
    )
    ownership_issues: list[str] = Field(
        description="Domains with unclear ownership",
    )


class QualityInsight(BaseModel):
    """Structured output from data quality assessment."""

    summary: str = Field(
        description="Data quality assessment overview",
    )
    failing_products: list[str] = Field(
        description="Data products failing quality thresholds",
    )
    recommendations: list[str] = Field(
        description="Quality improvement recommendations",
    )


class FederationInsight(BaseModel):
    """Structured output from federated query analysis."""

    summary: str = Field(
        description="Federation analysis overview",
    )
    cross_domain_findings: list[str] = Field(
        description="Findings from cross-domain queries",
    )
    correlation_patterns: list[str] = Field(
        description="Correlated patterns across domains",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of data mesh analysis",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a security data mesh analyst reviewing "
    "domain topology and data products.\n"
    "1. Identify gaps in domain coverage\n"
    "2. Assess data product freshness and quality\n"
    "3. Detect ownership and SLA issues\n"
    "4. Recommend federated query optimizations"
)

SYSTEM_REPORT = (
    "You are a security data advisor generating an "
    "executive data mesh health report.\n"
    "1. Summarize domain health and product quality\n"
    "2. Highlight cross-domain correlation insights\n"
    "3. Quantify data mesh coverage and gaps\n"
    "4. Recommend governance improvements"
)
