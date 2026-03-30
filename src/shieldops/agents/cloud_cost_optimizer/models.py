"""Cloud Cost Optimizer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CCOStage(StrEnum):
    COLLECT_BILLING = "collect_billing"
    ANALYZE_SPENDING = "analyze_spending"
    IDENTIFY_WASTE = "identify_waste"
    RECOMMEND_SAVINGS = "recommend_savings"
    IMPLEMENT_OPTIMIZATIONS = "implement_optimizations"
    REPORT = "report"


class CostCategory(StrEnum):
    COMPUTE = "compute"
    STORAGE = "storage"
    NETWORK = "network"
    DATABASE = "database"
    SERVERLESS = "serverless"
    LICENSING = "licensing"


class SavingsPotential(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"
    NEGATIVE = "negative"


class BillingRecord(BaseModel):
    """A billing line item from a cloud provider."""

    id: str = ""
    resource_id: str = ""
    category: CostCategory = CostCategory.COMPUTE
    provider: str = ""
    region: str = ""
    daily_cost: float = 0.0
    monthly_cost: float = 0.0
    utilization_pct: float = 0.0
    tags: dict[str, str] = Field(default_factory=dict)


class SpendingAnalysis(BaseModel):
    """Spending analysis result for a category."""

    category: CostCategory = CostCategory.COMPUTE
    total_monthly: float = 0.0
    trend: str = ""
    budget_pct: float = 0.0
    top_resources: list[str] = Field(default_factory=list)


class WasteItem(BaseModel):
    """An identified waste opportunity."""

    id: str = ""
    resource_id: str = ""
    category: CostCategory = CostCategory.COMPUTE
    waste_type: str = ""
    monthly_waste: float = 0.0
    utilization_pct: float = 0.0
    recommendation: str = ""
    savings: SavingsPotential = SavingsPotential.MEDIUM


class SavingsRecommendation(BaseModel):
    """A savings recommendation."""

    id: str = ""
    resource_id: str = ""
    action: str = ""
    description: str = ""
    estimated_monthly_savings: float = 0.0
    auto_executable: bool = False
    priority: str = "medium"
    risk: str = "low"


class OptimizationResult(BaseModel):
    """Result of an optimization implementation."""

    id: str = ""
    recommendation_id: str = ""
    status: str = ""
    actual_savings: float = 0.0
    rollback_available: bool = True


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudCostOptimizerState(BaseModel):
    """Main state for the Cloud Cost Optimizer agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CCOStage = CCOStage.COLLECT_BILLING

    billing_records: list[BillingRecord] = Field(
        default_factory=list,
    )
    spending_analysis: list[SpendingAnalysis] = Field(
        default_factory=list,
    )
    waste_items: list[WasteItem] = Field(
        default_factory=list,
    )
    recommendations: list[SavingsRecommendation] = Field(
        default_factory=list,
    )
    optimizations: list[OptimizationResult] = Field(
        default_factory=list,
    )

    report: str = ""
    total_monthly_spend: float = 0.0
    total_savings_potential: float = 0.0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
