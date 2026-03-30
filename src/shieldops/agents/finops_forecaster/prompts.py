"""FinOps Forecaster Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class TrendInsight(BaseModel):
    """Structured output from trend analysis."""

    summary: str = Field(
        description="Brief trend overview",
    )
    cost_drivers: list[str] = Field(
        description="Top cost growth drivers",
    )
    seasonal_patterns: list[str] = Field(
        description="Seasonal spending patterns",
    )


class ForecastInsight(BaseModel):
    """Structured output from spend forecasting."""

    summary: str = Field(
        description="Forecast overview",
    )
    overrun_risks: list[str] = Field(
        description="Services at risk of budget overrun",
    )
    optimization_areas: list[str] = Field(
        description="Areas with optimization potential",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive forecast summary",
    )
    key_findings: list[str] = Field(
        description="Key findings for leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_TRENDS = (
    "You are a FinOps analyst reviewing cloud "
    "spending trends.\n"
    "1. Identify services with fastest growth\n"
    "2. Detect seasonal patterns in spending\n"
    "3. Flag cost drivers and anomalies\n"
    "4. Compare trends across providers"
)

SYSTEM_FORECAST = (
    "You are a FinOps forecaster predicting "
    "future cloud spending.\n"
    "1. Project spending for each service\n"
    "2. Identify budget overrun risks\n"
    "3. Recommend commitment purchases\n"
    "4. Quantify potential savings from RIs"
)

SYSTEM_REPORT = (
    "You are a FinOps advisor generating an "
    "executive spending forecast report.\n"
    "1. Summarize forecasted spend and trends\n"
    "2. Highlight budget overrun risks\n"
    "3. Quantify commitment savings potential\n"
    "4. Recommend next steps for cost control"
)
