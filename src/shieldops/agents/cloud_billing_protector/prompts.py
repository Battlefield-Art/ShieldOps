"""Cloud Billing Protector Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class PatternInsight(BaseModel):
    """Structured output from billing pattern analysis."""

    summary: str = Field(
        description="Brief billing pattern overview",
    )
    spikes: list[str] = Field(
        description="Detected cost spikes",
    )
    unusual_services: list[str] = Field(
        description="Services with unusual spend",
    )


class FraudInsight(BaseModel):
    """Structured output from fraud classification."""

    summary: str = Field(
        description="Fraud classification overview",
    )
    confirmed_fraud: list[str] = Field(
        description="Confirmed fraudulent activities",
    )
    indicators: list[str] = Field(
        description="Key fraud indicators detected",
    )


class AnomalyInsight(BaseModel):
    """Structured output from anomaly detection."""

    summary: str = Field(
        description="Anomaly detection overview",
    )
    top_anomalies: list[str] = Field(
        description="Most significant anomalies",
    )
    recommendations: list[str] = Field(
        description="Mitigation recommendations",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of billing protection",
    )
    key_findings: list[str] = Field(
        description="Key findings for finance/security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a cloud FinOps security analyst reviewing "
    "billing data for fraud and abuse.\n"
    "1. Identify cryptomining indicators (GPU spikes)\n"
    "2. Detect resource hijacking patterns\n"
    "3. Flag unauthorized resource provisioning\n"
    "4. Assess budget overrun severity"
)

SYSTEM_REPORT = (
    "You are a cloud billing security advisor generating "
    "an executive fraud detection report.\n"
    "1. Summarize anomalies by type and severity\n"
    "2. Highlight confirmed fraud with estimated loss\n"
    "3. Quantify total exposure and savings\n"
    "4. Recommend budget enforcement improvements"
)
