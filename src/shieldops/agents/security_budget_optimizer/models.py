"""State models for the Security Budget Optimizer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class SBOStage(StrEnum):
    """Workflow stages for security budget optimization."""

    INVENTORY_TOOLS = "inventory_tools"
    MEASURE_EFFECTIVENESS = "measure_effectiveness"
    ANALYZE_OVERLAP = "analyze_overlap"
    OPTIMIZE_BUDGET = "optimize_budget"
    FORECAST = "forecast"
    REPORT = "report"


class ToolCategory(StrEnum):
    """Security tool categories."""

    EDR = "edr"
    SIEM = "siem"
    SOAR = "soar"
    IAM = "iam"
    VULN_MGMT = "vuln_mgmt"
    CLOUD_SECURITY = "cloud_security"
    DLP = "dlp"


class InvestmentPriority(StrEnum):
    """Budget investment priority levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    DIVEST = "divest"


# ── Domain Models ─────────────────────────────────────


class SecurityTool(BaseModel):
    """A security tool in the organization's stack."""

    tool_id: str = ""
    name: str = ""
    vendor: str = ""
    category: ToolCategory = ToolCategory.EDR
    annual_cost: float = 0.0
    license_count: int = 0
    utilization_pct: float = 0.0
    contract_end: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class EffectivenessScore(BaseModel):
    """Effectiveness measurement for a security tool."""

    tool_id: str = ""
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    mttr_contribution_ms: int = 0
    incidents_handled: int = 0
    coverage_pct: float = 0.0
    roi_score: float = 0.0
    reasoning: str = ""


class OverlapAnalysis(BaseModel):
    """Overlap analysis between security tools."""

    tool_a: str = ""
    tool_b: str = ""
    overlap_pct: float = 0.0
    redundant_features: list[str] = Field(default_factory=list)
    consolidation_savings: float = 0.0
    risk_if_removed: str = "low"


class BudgetAllocation(BaseModel):
    """Optimized budget allocation recommendation."""

    alloc_id: str = ""
    tool_id: str = ""
    current_spend: float = 0.0
    recommended_spend: float = 0.0
    priority: InvestmentPriority = InvestmentPriority.MEDIUM
    action: str = ""
    savings: float = 0.0
    description: str = ""


class ROIForecast(BaseModel):
    """ROI forecast for budget changes."""

    forecast_id: str = ""
    scenario: str = ""
    projected_savings: float = 0.0
    risk_delta: float = 0.0
    payback_months: int = 0
    confidence: float = 0.0
    description: str = ""


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the optimizer workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityBudgetOptimizerState(BaseModel):
    """Full state for the Security Budget Optimizer."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: SBOStage = SBOStage.INVENTORY_TOOLS
    scan_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Inventory
    tools_inventory: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_spend: float = 0.0

    # Effectiveness
    effectiveness_scores: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    avg_roi: float = 0.0

    # Overlap
    overlap_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_overlap_savings: float = 0.0

    # Budget
    budget_allocations: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Forecast
    roi_forecasts: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
