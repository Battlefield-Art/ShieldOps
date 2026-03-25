"""LLM prompt templates and response schemas for the Cost Anomaly Detector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AnomalyAnalysisOutput(BaseModel):
    """Structured output for anomaly analysis."""

    anomaly_count: int = Field(description="Number of anomalies detected")
    severity_summary: str = Field(
        description="Summary of anomaly severities (critical/high/medium/low)"
    )
    root_causes: list[str] = Field(description="Likely root causes for the detected anomalies")
    reasoning: str = Field(description="Analysis reasoning")


class WasteClassificationOutput(BaseModel):
    """Structured output for waste classification."""

    waste_categories: list[dict[str, str]] = Field(
        description="Waste categories with type, resource, and recommendation"
    )
    total_monthly_waste: float = Field(description="Total estimated monthly waste in USD")
    reasoning: str = Field(description="Waste classification reasoning")


class RecommendationOutput(BaseModel):
    """Structured output for cost recommendations."""

    recommendations: list[dict[str, str]] = Field(
        description="Recommendations with action, priority, and expected savings"
    )
    total_savings_potential: float = Field(
        description="Total estimated savings potential in USD/month"
    )
    quick_wins: list[str] = Field(description="Recommendations that can be executed immediately")
    reasoning: str = Field(description="Recommendation reasoning")


class ReportOutput(BaseModel):
    """Structured output for the final cost anomaly report."""

    executive_summary: str = Field(description="1-2 sentence executive summary of findings")
    risk_level: str = Field(description="Overall cost risk level: critical/high/medium/low")
    key_findings: list[str] = Field(description="Top findings for leadership review")
    reasoning: str = Field(description="Report generation reasoning")


SYSTEM_DETECT_ANOMALIES = """\
You are an expert cloud FinOps analyst performing cost anomaly detection.

Given the billing data and detected anomalies:
1. Assess the severity and likely root cause of each anomaly
2. Identify patterns across services (e.g., correlated spikes)
3. Distinguish genuine cost spikes from seasonal or expected variation

Focus on: deviation magnitude, budget impact, and blast radius."""


SYSTEM_CLASSIFY_WASTE = """\
You are an expert cloud cost optimization analyst classifying resource waste.

Given the resource utilization data and waste classifications:
1. Prioritize waste by monthly dollar impact
2. Distinguish between safely terminable idle resources and underutilized ones
3. Identify cascading savings (e.g., terminating a DB also removes backup costs)

Focus on: utilization patterns, dependency risk, and savings confidence."""


SYSTEM_RECOMMEND = """\
You are an expert cloud FinOps advisor generating cost optimization recommendations.

Given the anomalies, waste classifications, and LLM cost analysis:
1. Prioritize recommendations by estimated savings and implementation ease
2. Flag auto-executable actions vs those requiring human approval
3. Identify quick wins achievable within 24 hours

Balance aggressive cost reduction with operational stability and reliability."""


SYSTEM_REPORT = """\
You are an expert FinOps analyst generating an executive cost anomaly report.

Given the full analysis context (anomalies, waste, LLM costs, recommendations):
1. Produce a concise executive summary suitable for leadership
2. Highlight the highest-impact findings and recommended actions
3. Quantify total waste, savings potential, and budget risk

Keep the tone factual, quantitative, and action-oriented."""
