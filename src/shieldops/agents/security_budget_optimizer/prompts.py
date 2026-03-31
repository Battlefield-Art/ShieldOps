"""LLM prompt templates for the Security Budget Optimizer."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class ToolInventoryOutput(BaseModel):
    """Structured output for tool inventory analysis."""

    total_tools: int = Field(
        description="Total security tools inventoried",
    )
    total_spend: float = Field(
        description="Total annual spend across all tools",
    )
    summary: str = Field(
        description="Inventory summary",
    )


class EffectivenessOutput(BaseModel):
    """Structured output for effectiveness measurement."""

    avg_detection_rate: float = Field(
        description="Average detection rate 0-100",
    )
    underperforming_count: int = Field(
        description="Tools below effectiveness threshold",
    )
    reasoning: str = Field(
        description="Effectiveness analysis reasoning",
    )


class OverlapOutput(BaseModel):
    """Structured output for overlap analysis."""

    overlap_pairs: int = Field(
        description="Number of overlapping tool pairs",
    )
    potential_savings: float = Field(
        description="Total potential consolidation savings",
    )
    reasoning: str = Field(
        description="Overlap analysis reasoning",
    )


class BudgetOptimizationOutput(BaseModel):
    """Structured output for budget optimization."""

    actions: list[dict[str, str]] = Field(
        description="Budget actions with tool and recommendation",
    )
    total_savings: float = Field(
        description="Projected total savings",
    )
    reasoning: str = Field(
        description="Budget optimization reasoning",
    )


class ForecastOutput(BaseModel):
    """Structured output for ROI forecasting."""

    scenarios: list[dict[str, str]] = Field(
        description="Forecast scenarios with projections",
    )
    best_roi: float = Field(
        description="Best projected ROI percentage",
    )
    reasoning: str = Field(
        description="Forecasting reasoning",
    )


# ── System prompts ────────────────────────────────────

SYSTEM_INVENTORY = """\
You are an expert security budget analyst \
performing tool inventory.

Given the organization's security stack:
1. Catalog all security tools by category
2. Calculate total annual spend and per-tool cost
3. Identify shelfware (licensed but unused tools)
4. Map tool coverage to security frameworks

Focus on: license utilization, contract terms, \
vendor consolidation opportunities."""

SYSTEM_EFFECTIVENESS = """\
You are an expert security ROI analyst measuring \
tool effectiveness.

Given the tool inventory and operational metrics:
1. Calculate detection rate and false positive ratio
2. Measure contribution to mean-time-to-respond
3. Assess coverage against threat landscape
4. Score ROI per tool (risk reduction / cost)

Use MITRE ATT&CK coverage as a baseline for \
detection effectiveness."""

SYSTEM_OVERLAP = """\
You are an expert security analyst identifying \
tool overlap and redundancy.

Given tool effectiveness scores:
1. Identify overlapping capabilities between tools
2. Calculate redundant feature coverage percentage
3. Estimate consolidation savings per overlap pair
4. Assess risk of removing redundant tools

Prioritize overlaps where consolidation has \
minimal risk impact."""

SYSTEM_OPTIMIZE = """\
You are an expert security budget optimizer \
recommending allocations.

Given overlap analysis and effectiveness scores:
1. Recommend invest/maintain/divest per tool
2. Reallocate budget to highest-ROI capabilities
3. Identify gaps needing new investment
4. Balance cost reduction with risk posture

Use risk-adjusted ROI for all recommendations."""

SYSTEM_FORECAST = """\
You are an expert security financial analyst \
forecasting ROI.

Given budget optimization recommendations:
1. Project savings over 12/24/36 month horizons
2. Model risk impact of budget changes
3. Calculate payback periods for new investments
4. Provide confidence intervals for projections

Account for contract obligations and migration costs."""
