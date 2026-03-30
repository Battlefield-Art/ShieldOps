"""FinOps Forecaster Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class FFStage(StrEnum):
    COLLECT_HISTORY = "collect_history"
    ANALYZE_TRENDS = "analyze_trends"
    FORECAST_SPEND = "forecast_spend"
    DETECT_ANOMALIES = "detect_anomalies"
    RECOMMEND_COMMITMENTS = "recommend_commitments"
    REPORT = "report"


class ForecastHorizon(StrEnum):
    ONE_MONTH = "one_month"
    THREE_MONTHS = "three_months"
    SIX_MONTHS = "six_months"
    ONE_YEAR = "one_year"


class CommitmentType(StrEnum):
    RESERVED_INSTANCE = "reserved_instance"
    SAVINGS_PLAN = "savings_plan"
    SPOT = "spot"
    ON_DEMAND = "on_demand"
    COMMITTED_USE = "committed_use"


class SpendHistory(BaseModel):
    """Monthly cloud spending record."""

    id: str = ""
    month: str = ""
    provider: str = ""
    service: str = ""
    region: str = ""
    amount: float = 0.0
    currency: str = "USD"
    tags: dict[str, str] = Field(default_factory=dict)


class TrendAnalysis(BaseModel):
    """Trend analysis for a service or provider."""

    id: str = ""
    service: str = ""
    provider: str = ""
    direction: str = ""
    growth_rate_pct: float = 0.0
    seasonality: str = ""
    avg_monthly: float = 0.0
    peak_month: str = ""
    trough_month: str = ""


class SpendForecast(BaseModel):
    """Projected spending for a future period."""

    id: str = ""
    service: str = ""
    provider: str = ""
    horizon: ForecastHorizon = ForecastHorizon.THREE_MONTHS
    projected_monthly: float = 0.0
    projected_total: float = 0.0
    confidence_pct: float = 0.0
    budget_limit: float = 0.0
    overrun_risk: bool = False
    overrun_amount: float = 0.0


class CostAnomaly(BaseModel):
    """A detected cost anomaly."""

    id: str = ""
    service: str = ""
    provider: str = ""
    month: str = ""
    expected_amount: float = 0.0
    actual_amount: float = 0.0
    deviation_pct: float = 0.0
    severity: str = "medium"
    explanation: str = ""


class CommitmentRecommendation(BaseModel):
    """Recommendation for a commitment purchase."""

    id: str = ""
    service: str = ""
    provider: str = ""
    commitment_type: CommitmentType = CommitmentType.RESERVED_INSTANCE
    term_months: int = 12
    upfront_cost: float = 0.0
    monthly_savings: float = 0.0
    annual_savings: float = 0.0
    break_even_months: int = 0
    confidence_pct: float = 0.0
    risk: str = "low"


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class FinopsForecasterState(BaseModel):
    """Main state for the FinOps Forecaster agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: FFStage = FFStage.COLLECT_HISTORY

    spend_history: list[SpendHistory] = Field(
        default_factory=list,
    )
    trend_analyses: list[TrendAnalysis] = Field(
        default_factory=list,
    )
    forecasts: list[SpendForecast] = Field(
        default_factory=list,
    )
    anomalies: list[CostAnomaly] = Field(
        default_factory=list,
    )
    commitments: list[CommitmentRecommendation] = Field(
        default_factory=list,
    )

    report: str = ""
    total_forecasted_spend: float = 0.0
    total_potential_savings: float = 0.0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
