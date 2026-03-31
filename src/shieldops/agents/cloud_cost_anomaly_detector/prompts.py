"""Cloud Cost Anomaly Detector Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class TrendInsight(BaseModel):
    """Structured output from spend trend analysis."""

    summary: str = Field(
        description="Brief cloud spending overview",
    )
    anomalous_services: list[str] = Field(
        description="Services with unusual spending patterns",
    )
    cost_drivers: list[str] = Field(
        description="Top cost drivers identified",
    )


class AnomalyInsight(BaseModel):
    """Structured output from anomaly detection."""

    summary: str = Field(
        description="Anomaly detection overview",
    )
    critical_anomalies: list[str] = Field(
        description="Critical cost anomalies found",
    )
    root_causes: list[str] = Field(
        description="Likely root causes",
    )


class ClassificationInsight(BaseModel):
    """Structured output from cause classification."""

    summary: str = Field(
        description="Cause classification overview",
    )
    remediable_items: list[str] = Field(
        description="Auto-remediable cost issues",
    )
    recommendations: list[str] = Field(
        description="Cost optimization recommendations",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of cost anomaly analysis",
    )
    key_findings: list[str] = Field(
        description="Key findings for finance and engineering",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a cloud FinOps analyst reviewing "
    "multi-cloud billing data.\n"
    "1. Identify services with abnormal spend increases\n"
    "2. Detect waste from orphaned or idle resources\n"
    "3. Flag reserved capacity that is underutilized\n"
    "4. Quantify deviation from historical baselines"
)

SYSTEM_REPORT = (
    "You are a FinOps advisor generating an "
    "executive cost anomaly report.\n"
    "1. Summarize anomalies by provider and severity\n"
    "2. Highlight savings opportunities\n"
    "3. Quantify total excess spend detected\n"
    "4. Recommend remediation actions"
)
