"""Security ROI Calculator Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class OutcomeInsight(BaseModel):
    """Structured output from outcome measurement analysis."""

    summary: str = Field(
        description="Brief outcome measurement overview",
    )
    high_value_outcomes: list[str] = Field(
        description="Highest-value security outcomes",
    )
    measurement_gaps: list[str] = Field(
        description="Gaps in outcome measurement",
    )


class ROIInsight(BaseModel):
    """Structured output from ROI calculation analysis."""

    summary: str = Field(
        description="ROI calculation overview",
    )
    best_investments: list[str] = Field(
        description="Best-performing investments by ROI",
    )
    underperformers: list[str] = Field(
        description="Underperforming investments to review",
    )


class ForecastInsight(BaseModel):
    """Structured output from value forecasting."""

    summary: str = Field(
        description="Forecast analysis overview",
    )
    growth_areas: list[str] = Field(
        description="Areas with highest projected growth",
    )
    risk_factors: list[str] = Field(
        description="Risk factors for forecast accuracy",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of security ROI",
    )
    key_findings: list[str] = Field(
        description="Key findings for leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ROI = (
    "You are a security investment analyst reviewing "
    "ROI calculations for security tools.\n"
    "1. Evaluate cost-effectiveness of each investment\n"
    "2. Identify highest-value security spending\n"
    "3. Compare against industry benchmarks\n"
    "4. Recommend investment optimization strategy"
)

SYSTEM_REPORT = (
    "You are a security finance advisor generating "
    "an executive ROI assessment report.\n"
    "1. Summarize total security investment and returns\n"
    "2. Highlight best and worst performing investments\n"
    "3. Present industry benchmark comparisons\n"
    "4. Recommend budget reallocation for maximum ROI"
)
