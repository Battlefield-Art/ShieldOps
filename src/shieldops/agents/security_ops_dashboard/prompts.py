"""Security Ops Dashboard Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class KPIInsight(BaseModel):
    """Structured output from KPI analysis."""

    summary: str = Field(
        description="Brief KPI performance overview",
    )
    underperforming_kpis: list[str] = Field(
        description="KPIs not meeting targets",
    )
    improvement_areas: list[str] = Field(
        description="Areas for operational improvement",
    )


class AnomalyInsight(BaseModel):
    """Structured output from anomaly detection."""

    summary: str = Field(
        description="Anomaly detection overview",
    )
    critical_anomalies: list[str] = Field(
        description="Critical anomalies requiring attention",
    )
    root_causes: list[str] = Field(
        description="Probable root causes identified",
    )


class ExecutiveInsight(BaseModel):
    """Structured output from insight generation."""

    summary: str = Field(
        description="Executive insight overview",
    )
    key_actions: list[str] = Field(
        description="Key actions for leadership",
    )
    risk_areas: list[str] = Field(
        description="Emerging risk areas",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of security operations health",
    )
    key_findings: list[str] = Field(
        description="Key findings for security leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_KPI = (
    "You are a security operations analyst reviewing "
    "KPI performance data.\n"
    "1. Evaluate MTTD, MTTR, and detection coverage\n"
    "2. Assess alert volume trends and false positive rates\n"
    "3. Track team productivity and workload balance\n"
    "4. Identify KPIs trending below target"
)

SYSTEM_REPORT = (
    "You are a security operations advisor generating an "
    "executive dashboard report.\n"
    "1. Summarize operational health across all KPIs\n"
    "2. Highlight anomalies and emerging trends\n"
    "3. Report on team performance and capacity\n"
    "4. Recommend operational improvements"
)
