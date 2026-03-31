"""Alert Fatigue Reducer Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class NoiseInsight(BaseModel):
    """Structured output from noise analysis."""

    summary: str = Field(
        description="Brief alert noise overview",
    )
    noisiest_rules: list[str] = Field(
        description="Rules generating the most noise",
    )
    dedup_opportunities: list[str] = Field(
        description="Deduplication opportunities",
    )


class FatigueInsight(BaseModel):
    """Structured output from fatigue detection."""

    summary: str = Field(
        description="Fatigue detection overview",
    )
    at_risk_analysts: list[str] = Field(
        description="Analysts at burnout risk",
    )
    root_causes: list[str] = Field(
        description="Root causes of alert fatigue",
    )


class TuningInsight(BaseModel):
    """Structured output from rule tuning."""

    summary: str = Field(
        description="Rule tuning overview",
    )
    safe_tunings: list[str] = Field(
        description="Safe tuning recommendations",
    )
    risky_tunings: list[str] = Field(
        description="Tunings requiring caution",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of alert fatigue reduction",
    )
    key_findings: list[str] = Field(
        description="Key findings for SOC leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a SOC alert analyst reviewing "
    "alert noise and fatigue patterns.\n"
    "1. Identify duplicate and redundant alert rules\n"
    "2. Flag rules with high false positive rates\n"
    "3. Detect analyst fatigue from dismiss patterns\n"
    "4. Recommend threshold and dedup optimizations"
)

SYSTEM_REPORT = (
    "You are a SOC operations advisor generating an "
    "alert fatigue reduction report.\n"
    "1. Summarize noise reduction opportunities\n"
    "2. Highlight analyst fatigue risk levels\n"
    "3. Quantify expected alert volume reduction\n"
    "4. Recommend safe rule tuning priorities"
)
