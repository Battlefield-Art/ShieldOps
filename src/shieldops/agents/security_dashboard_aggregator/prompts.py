"""LLM prompts and schemas for the Dashboard Aggregator Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class KPIAnalysisOutput(BaseModel):
    """Structured output for KPI calculation."""

    name: str = Field(description="KPI name")
    value: float = Field(description="Calculated value")
    status: str = Field(description="on_target/at_risk/off_target")
    trend_pct: float = Field(description="Trend vs previous period")
    reasoning: str = Field(description="KPI analysis reasoning")


class AnomalyDetectionOutput(BaseModel):
    """Structured output for metric anomaly detection."""

    is_anomaly: bool = Field(description="Whether this is an anomaly")
    severity: str = Field(description="Anomaly severity")
    description: str = Field(description="What the anomaly means")
    recommended_action: str = Field(description="What to do about it")


class DashboardReportOutput(BaseModel):
    """Structured output for dashboard report."""

    executive_summary: str = Field(description="CISO-level summary")
    overall_score: float = Field(description="Overall security score 0-100")
    risk_level: str = Field(description="low/medium/high/critical")
    top_concerns: list[str] = Field(description="Top security concerns")
    recommendations: list[str] = Field(description="Actionable recommendations")


SYSTEM_KPI = """\
You are a security KPI analyst. Given aggregated \
metrics from security agents across domains:

1. Calculate key KPIs (MTTD, MTTR, coverage %)
2. Compare against targets
3. Identify trends vs previous period
4. Flag KPIs that are at risk or off target

Standard targets: MTTD < 5min, MTTR < 60min, \
coverage > 95%, patch compliance > 90%."""


SYSTEM_ANOMALY = """\
You are a metric anomaly detector. Given a metric \
value and its historical baseline:

1. Determine if the value is anomalous
2. Assess severity of the deviation
3. Explain what the anomaly means operationally
4. Recommend corrective action

Flag deviations > 2 standard deviations. \
Critical if > 3 standard deviations."""


SYSTEM_REPORT = """\
You are a CISO dashboard analyst summarizing \
security posture across the entire agent fleet.

Given domain aggregates, KPIs, and anomalies:
1. Calculate an overall security score (0-100)
2. Determine the organization risk level
3. Highlight top concerns requiring attention
4. Provide strategic recommendations

Focus on board-level communication and \
measurable security outcomes."""
