"""Incident Prediction Model Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class PredictionInsight(BaseModel):
    """Structured output from prediction model analysis."""

    summary: str = Field(
        description="Brief prediction model overview",
    )
    high_risk_predictions: list[str] = Field(
        description="Highest risk incident predictions",
    )
    key_indicators: list[str] = Field(
        description="Most significant leading indicators",
    )


class ConfidenceInsight(BaseModel):
    """Structured output from confidence assessment."""

    summary: str = Field(
        description="Confidence assessment overview",
    )
    reliable_predictions: list[str] = Field(
        description="Predictions with high confidence",
    )
    data_gaps: list[str] = Field(
        description="Areas where more data would improve accuracy",
    )


class WarningInsight(BaseModel):
    """Structured output from warning generation."""

    summary: str = Field(
        description="Early warning generation overview",
    )
    urgent_warnings: list[str] = Field(
        description="Warnings requiring immediate attention",
    )
    preventive_actions: list[str] = Field(
        description="Recommended preventive actions",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of incident predictions",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a predictive security analyst reviewing "
    "leading indicators and model outputs.\n"
    "1. Identify the most significant leading indicators\n"
    "2. Assess prediction reliability and confidence\n"
    "3. Prioritize warnings by risk and time horizon\n"
    "4. Recommend proactive defensive actions"
)

SYSTEM_REPORT = (
    "You are a security advisor generating an "
    "incident prediction report.\n"
    "1. Summarize predictions by incident type and risk\n"
    "2. Highlight imminent threats requiring action\n"
    "3. Quantify prediction confidence and accuracy\n"
    "4. Recommend risk mitigation strategies"
)
