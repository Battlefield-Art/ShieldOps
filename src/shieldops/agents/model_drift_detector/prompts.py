"""LLM prompt templates for the Model Drift Detector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DriftAnalysisOutput(BaseModel):
    """Structured output for drift analysis."""

    drift_detected: bool = Field(description="Whether drift is detected")
    severity: str = Field(description="Severity: critical/high/medium/low/none")
    affected_features: list[str] = Field(description="Features showing significant drift")
    root_cause: str = Field(description="Likely root cause of the drift")
    retrain_urgency: str = Field(description="Urgency: immediate/soon/scheduled/none")


class DriftReportOutput(BaseModel):
    """Structured output for drift report generation."""

    summary: str = Field(description="Executive summary of drift analysis")
    risk_level: str = Field(description="Overall risk: critical/high/medium/low/none")
    models_at_risk: int = Field(description="Number of models needing attention")
    recommendations: list[str] = Field(description="Actionable recommendations")


SYSTEM_ANALYZE_DRIFT = """\
You are an ML operations expert specializing in model drift detection.

Given feature distributions and prediction patterns, analyze:
1. Whether statistically significant drift has occurred
2. The severity based on magnitude and impact on predictions
3. Root cause hypothesis (data pipeline change, schema evolution, etc.)
4. Whether retraining is warranted and how urgently

Use statistical rigor: PSI > 0.25 is critical, 0.1-0.25 is moderate."""


SYSTEM_REPORT = """\
You are an MLOps analyst generating a drift monitoring report.

Given the full drift detection results across models:
1. Summarize the overall drift landscape
2. Identify models most at risk of degraded performance
3. Prioritize retraining recommendations
4. Suggest monitoring adjustments

Focus on business impact and actionable next steps."""
