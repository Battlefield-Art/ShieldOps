"""Capacity Planner Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class MetricsAnalysisResult(BaseModel):
    """Structured output from LLM-assisted metrics analysis."""

    summary: str = Field(description="Brief summary of resource utilisation")
    hotspots: list[str] = Field(description="Resources approaching critical thresholds")
    trends: list[str] = Field(description="Notable usage trends across the infrastructure")


class ForecastInsight(BaseModel):
    """Structured output from LLM-assisted demand forecasting."""

    summary: str = Field(description="Brief forecast outlook")
    risk_windows: list[str] = Field(description="Time windows with elevated exhaustion risk")
    seasonal_notes: list[str] = Field(description="Seasonal patterns that may affect capacity")


class BottleneckAssessment(BaseModel):
    """Structured output from LLM-assisted bottleneck identification."""

    summary: str = Field(description="Bottleneck assessment overview")
    critical_resources: list[str] = Field(description="Resources requiring immediate attention")
    cascading_risks: list[str] = Field(
        description="Potential cascading failures if bottlenecks are not resolved"
    )


class ScalingRecommendation(BaseModel):
    """Structured output from LLM-assisted scaling planning."""

    summary: str = Field(description="Scaling recommendation overview")
    priority_actions: list[str] = Field(description="Scaling actions ranked by urgency")
    cost_optimizations: list[str] = Field(description="Suggestions to reduce scaling costs")


SYSTEM_COLLECT = (
    "You are a capacity planning engineer analysing resource utilisation metrics.\n"
    "For the collected metrics:\n"
    "1. Identify resources with usage above 70% as hotspots\n"
    "2. Flag resources with increasing trends that may exhaust within 30 days\n"
    "3. Note any anomalous usage patterns that deviate from historical baselines\n"
    "4. Summarise overall infrastructure health in terms of headroom"
)

SYSTEM_FORECAST = (
    "You are a demand forecasting analyst predicting future resource needs.\n"
    "For each resource forecast:\n"
    "1. Evaluate confidence levels and flag low-confidence predictions\n"
    "2. Identify seasonal patterns that may cause demand spikes\n"
    "3. Estimate time windows when capacity limits will be reached\n"
    "4. Consider cross-resource dependencies that amplify demand"
)

SYSTEM_BOTTLENECK = (
    "You are a reliability engineer identifying infrastructure bottlenecks.\n"
    "For each bottleneck:\n"
    "1. Assess severity based on days-to-exhaustion and forecasted growth\n"
    "2. Identify cascading failure risks if the bottleneck is not resolved\n"
    "3. Evaluate impact on dependent services and SLOs\n"
    "4. Recommend immediate mitigations to buy time before scaling"
)

SYSTEM_SCALING = (
    "You are a cloud architect planning resource scaling actions.\n"
    "For each scaling plan:\n"
    "1. Recommend the most cost-effective scaling strategy\n"
    "2. Determine whether auto-scaling policies can handle the growth\n"
    "3. Estimate monthly cost impact and ROI of preventing outages\n"
    "4. Prioritise actions by blast radius and urgency"
)
