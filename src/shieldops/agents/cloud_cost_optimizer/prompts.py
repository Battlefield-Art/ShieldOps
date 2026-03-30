"""Cloud Cost Optimizer Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class SpendingInsight(BaseModel):
    """Structured output from spending analysis."""

    summary: str = Field(
        description="Brief spending overview",
    )
    hotspots: list[str] = Field(
        description="Top cost hotspots",
    )
    trends: list[str] = Field(
        description="Notable spending trends",
    )


class WasteInsight(BaseModel):
    """Structured output from waste identification."""

    summary: str = Field(
        description="Waste identification overview",
    )
    quick_wins: list[str] = Field(
        description="Quick-win waste elimination items",
    )
    risk_areas: list[str] = Field(
        description="Areas needing careful review",
    )


class SavingsInsight(BaseModel):
    """Structured output from savings recommendations."""

    summary: str = Field(
        description="Savings recommendation overview",
    )
    priority_actions: list[str] = Field(
        description="Highest-priority savings actions",
    )
    cost_optimizations: list[str] = Field(
        description="Additional cost optimization ideas",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of cost optimization",
    )
    key_findings: list[str] = Field(
        description="Key findings for leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a cloud FinOps analyst reviewing "
    "spending patterns.\n"
    "1. Identify the top cost categories and drivers\n"
    "2. Flag categories exceeding budget thresholds\n"
    "3. Detect spending trends and anomalies\n"
    "4. Compare costs across providers and regions"
)

SYSTEM_REPORT = (
    "You are a FinOps advisor generating an "
    "executive cost optimization report.\n"
    "1. Summarize total spend, waste, and savings\n"
    "2. Highlight highest-impact recommendations\n"
    "3. Quantify ROI of proposed optimizations\n"
    "4. Recommend next steps for cost governance"
)
