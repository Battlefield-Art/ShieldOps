"""Security ROI Calculator Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SRCStage(StrEnum):
    COLLECT_INVESTMENTS = "collect_investments"
    MEASURE_OUTCOMES = "measure_outcomes"
    CALCULATE_ROI = "calculate_roi"
    COMPARE_BENCHMARKS = "compare_benchmarks"
    FORECAST = "forecast"
    REPORT = "report"


class InvestmentCategory(StrEnum):
    TOOLING = "tooling"
    PERSONNEL = "personnel"
    TRAINING = "training"
    CONSULTING = "consulting"
    INFRASTRUCTURE = "infrastructure"
    COMPLIANCE = "compliance"


class OutcomeType(StrEnum):
    BREACH_PREVENTION = "breach_prevention"
    RISK_REDUCTION = "risk_reduction"
    COMPLIANCE_SAVINGS = "compliance_savings"
    EFFICIENCY_GAIN = "efficiency_gain"
    INCIDENT_REDUCTION = "incident_reduction"


class Investment(BaseModel):
    """A single security investment record."""

    id: str = ""
    category: InvestmentCategory = InvestmentCategory.TOOLING
    name: str = ""
    annual_cost: float = 0.0
    start_date: str = ""
    vendor: str = ""
    headcount_fte: float = 0.0
    contract_months: int = 12


class Outcome(BaseModel):
    """A measured security outcome."""

    id: str = ""
    outcome_type: OutcomeType = OutcomeType.RISK_REDUCTION
    description: str = ""
    value_usd: float = 0.0
    measurement_period: str = ""
    confidence: float = 0.0
    linked_investment_id: str = ""


class ROIResult(BaseModel):
    """ROI calculation for an investment."""

    id: str = ""
    investment_id: str = ""
    investment_name: str = ""
    total_cost: float = 0.0
    total_value: float = 0.0
    roi_pct: float = 0.0
    payback_months: int = 0
    net_value: float = 0.0


class BenchmarkComparison(BaseModel):
    """Industry benchmark comparison."""

    id: str = ""
    category: str = ""
    org_spend_pct: float = 0.0
    industry_avg_pct: float = 0.0
    percentile: int = 50
    recommendation: str = ""


class ForecastResult(BaseModel):
    """Value forecast for future periods."""

    id: str = ""
    period: str = ""
    projected_cost: float = 0.0
    projected_value: float = 0.0
    projected_roi_pct: float = 0.0
    confidence_interval: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityROICalculatorState(BaseModel):
    """Main state for the Security ROI Calculator agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SRCStage = SRCStage.COLLECT_INVESTMENTS

    investments: list[Investment] = Field(
        default_factory=list,
    )
    outcomes: list[Outcome] = Field(
        default_factory=list,
    )
    roi_results: list[ROIResult] = Field(
        default_factory=list,
    )
    benchmarks: list[BenchmarkComparison] = Field(
        default_factory=list,
    )
    forecasts: list[ForecastResult] = Field(
        default_factory=list,
    )

    report: str = ""
    total_investment: float = 0.0
    overall_roi_pct: float = 0.0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
