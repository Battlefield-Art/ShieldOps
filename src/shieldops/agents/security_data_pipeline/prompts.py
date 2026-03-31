"""Security Data Pipeline Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class TransformInsight(BaseModel):
    """Structured output from data transformation analysis."""

    summary: str = Field(
        description="Brief data transformation overview",
    )
    schema_issues: list[str] = Field(
        description="Detected schema normalization issues",
    )
    recommendations: list[str] = Field(
        description="Transformation recommendations",
    )


class QualityInsight(BaseModel):
    """Structured output from data quality analysis."""

    summary: str = Field(
        description="Data quality assessment overview",
    )
    critical_issues: list[str] = Field(
        description="Critical quality issues found",
    )
    remediation_steps: list[str] = Field(
        description="Steps to improve data quality",
    )


class EnrichmentInsight(BaseModel):
    """Structured output from enrichment analysis."""

    summary: str = Field(
        description="Enrichment results overview",
    )
    high_risk_iocs: list[str] = Field(
        description="High-risk IOCs discovered",
    )
    coverage_gaps: list[str] = Field(
        description="Enrichment coverage gaps",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of pipeline run",
    )
    key_findings: list[str] = Field(
        description="Key findings from pipeline execution",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_TRANSFORM = (
    "You are a security data engineer reviewing "
    "ETL transformation results.\n"
    "1. Evaluate schema normalization quality\n"
    "2. Identify missing or malformed fields\n"
    "3. Check OCSF compliance of output records\n"
    "4. Recommend pipeline optimization steps"
)

SYSTEM_REPORT = (
    "You are a security data pipeline advisor "
    "generating an executive pipeline report.\n"
    "1. Summarize ingestion and transformation stats\n"
    "2. Highlight enrichment hit rates and IOC matches\n"
    "3. Quantify data quality across all sources\n"
    "4. Recommend pipeline tuning for next cycle"
)
