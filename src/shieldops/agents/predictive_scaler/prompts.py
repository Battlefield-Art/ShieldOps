"""Predictive Scaler Agent — LLM prompt templates."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PatternInsight(BaseModel):
    """Structured output from pattern analysis."""

    summary: str = Field(
        description="Brief pattern analysis overview",
    )
    seasonality: list[str] = Field(
        description="Detected seasonal patterns",
    )
    anomalies: list[str] = Field(
        description="Notable anomalies or outliers",
    )


class PredictionInsight(BaseModel):
    """Structured output from demand prediction."""

    summary: str = Field(
        description="Demand forecast overview",
    )
    high_risk_resources: list[str] = Field(
        description="Resources at risk of overload",
    )
    recommended_actions: list[str] = Field(
        description="Proactive scaling recommendations",
    )


class ScalingInsight(BaseModel):
    """Structured output from scaling plan review."""

    summary: str = Field(
        description="Scaling plan overview",
    )
    cost_impact: list[str] = Field(
        description="Cost implications of scaling",
    )
    risk_factors: list[str] = Field(
        description="Risks to consider before scaling",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive scaling summary",
    )
    key_findings: list[str] = Field(
        description="Key findings for leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE_PATTERNS = (
    "You are an infrastructure capacity analyst "
    "reviewing resource utilization patterns.\n"
    "1. Identify cyclical demand patterns\n"
    "2. Detect growth trends and anomalies\n"
    "3. Flag resources approaching capacity\n"
    "4. Note correlation between resources"
)

SYSTEM_PREDICT_DEMAND = (
    "You are a demand forecasting specialist "
    "predicting infrastructure load.\n"
    "1. Forecast demand for the next 1-6 hours\n"
    "2. Identify resources likely to breach\n"
    "3. Estimate confidence of each prediction\n"
    "4. Recommend pre-emptive scaling actions"
)

SYSTEM_PLAN_SCALING = (
    "You are an infrastructure scaling advisor "
    "reviewing proposed scaling plans.\n"
    "1. Evaluate cost-benefit of each action\n"
    "2. Identify dependencies between resources\n"
    "3. Flag plans with high blast radius\n"
    "4. Recommend optimal execution order"
)

SYSTEM_REPORT = (
    "You are a platform engineering advisor "
    "generating a predictive scaling report.\n"
    "1. Summarize scaling actions and outcomes\n"
    "2. Highlight capacity risks averted\n"
    "3. Quantify cost impact of proactive scaling\n"
    "4. Recommend improvements to scaling policy"
)
