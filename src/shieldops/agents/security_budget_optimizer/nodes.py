"""Node implementations for the Security Budget Optimizer."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_budget_optimizer.models import (
    ReasoningStep,
    SBOStage,
    SecurityBudgetOptimizerState,
)
from shieldops.agents.security_budget_optimizer.prompts import (
    SYSTEM_EFFECTIVENESS,
    SYSTEM_FORECAST,
    SYSTEM_INVENTORY,
    SYSTEM_OPTIMIZE,
    SYSTEM_OVERLAP,
    BudgetOptimizationOutput,
    EffectivenessOutput,
    ForecastOutput,
    OverlapOutput,
    ToolInventoryOutput,
)
from shieldops.agents.security_budget_optimizer.tools import (
    SecurityBudgetOptimizerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityBudgetOptimizerToolkit | None = None


def set_toolkit(
    toolkit: SecurityBudgetOptimizerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityBudgetOptimizerToolkit:
    if _toolkit is None:
        return SecurityBudgetOptimizerToolkit()
    return _toolkit


def _step(
    state: SecurityBudgetOptimizerState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Create a reasoning step."""
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def inventory_tools(
    state: SecurityBudgetOptimizerState,
) -> dict[str, Any]:
    """Inventory all security tools."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.inventory_tools(state.scan_config)
    total_spend = sum(t.get("annual_cost", 0) for t in raw)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "organization": state.scan_config.get("organization", ""),
                "tool_count": len(raw),
                "total_spend": total_spend,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INVENTORY,
            user_prompt=(f"Tool inventory context:\n{ctx}"),
            schema=ToolInventoryOutput,
        )
        if hasattr(llm_result, "total_spend") and llm_result.total_spend > total_spend:
            total_spend = llm_result.total_spend
        logger.info(
            "llm_enhanced",
            node="inventory_tools",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="inventory_tools",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "inventory_tools",
        f"org={state.scan_config.get('organization', '')}",
        f"found {len(raw)} tools, ${total_spend:,.0f} spend",
        elapsed,
        "asset_inventory",
    )
    await toolkit.record_metric("tool_count", float(len(raw)))

    return {
        "tools_inventory": raw,
        "total_spend": round(total_spend, 2),
        "stage": SBOStage.MEASURE_EFFECTIVENESS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "inventory_tools",
        "session_start": start,
    }


async def measure_effectiveness(
    state: SecurityBudgetOptimizerState,
) -> dict[str, Any]:
    """Measure effectiveness of each tool."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scores = await toolkit.measure_effectiveness(
        state.tools_inventory,
    )
    avg_roi = 0.0
    if scores:
        avg_roi = round(
            sum(s.get("roi_score", 0) for s in scores) / len(scores),
            2,
        )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "tool_count": len(state.tools_inventory),
                "scores": scores[:10],
                "avg_roi": avg_roi,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_EFFECTIVENESS,
            user_prompt=(f"Effectiveness context:\n{ctx}"),
            schema=EffectivenessOutput,
        )
        if hasattr(llm_result, "avg_detection_rate"):
            logger.info(
                "llm_enhanced",
                node="measure_effectiveness",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="measure_effectiveness",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "measure_effectiveness",
        f"measuring {len(state.tools_inventory)} tools",
        f"avg ROI={avg_roi}",
        elapsed,
        "metrics_store",
    )

    return {
        "effectiveness_scores": scores,
        "avg_roi": avg_roi,
        "stage": SBOStage.ANALYZE_OVERLAP,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "measure_effectiveness",
    }


async def analyze_overlap(
    state: SecurityBudgetOptimizerState,
) -> dict[str, Any]:
    """Analyze overlap between tools."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    overlaps = await toolkit.analyze_overlap(
        state.tools_inventory,
        state.effectiveness_scores,
    )
    total_savings = sum(o.get("consolidation_savings", 0) for o in overlaps)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "tool_count": len(state.tools_inventory),
                "overlaps": overlaps[:10],
                "total_savings": total_savings,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_OVERLAP,
            user_prompt=(f"Overlap analysis context:\n{ctx}"),
            schema=OverlapOutput,
        )
        if (
            hasattr(llm_result, "potential_savings")
            and llm_result.potential_savings > total_savings
        ):
            total_savings = llm_result.potential_savings
        logger.info(
            "llm_enhanced",
            node="analyze_overlap",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_overlap",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "analyze_overlap",
        f"analyzing {len(state.tools_inventory)} tools",
        f"{len(overlaps)} overlaps, ${total_savings:,.0f} savings",
        elapsed,
        "overlap_analyzer",
    )
    await toolkit.record_metric("overlap_savings", total_savings)

    return {
        "overlap_analyses": overlaps,
        "total_overlap_savings": round(total_savings, 2),
        "stage": SBOStage.OPTIMIZE_BUDGET,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_overlap",
    }


async def optimize_budget(
    state: SecurityBudgetOptimizerState,
) -> dict[str, Any]:
    """Generate optimized budget allocations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    allocations = await toolkit.optimize_budget(
        state.tools_inventory,
        state.effectiveness_scores,
        state.overlap_analyses,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "tool_count": len(state.tools_inventory),
                "overlap_count": len(state.overlap_analyses),
                "allocations": allocations[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_OPTIMIZE,
            user_prompt=(f"Budget optimization context:\n{ctx}"),
            schema=BudgetOptimizationOutput,
        )
        if hasattr(llm_result, "actions"):
            logger.info(
                "llm_enhanced",
                node="optimize_budget",
                llm_actions=len(llm_result.actions),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="optimize_budget",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "optimize_budget",
        f"optimizing {len(state.tools_inventory)} tools",
        f"created {len(allocations)} allocations",
        elapsed,
        "budget_optimizer",
    )

    return {
        "budget_allocations": allocations,
        "stage": SBOStage.FORECAST,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "optimize_budget",
    }


async def forecast_roi(
    state: SecurityBudgetOptimizerState,
) -> dict[str, Any]:
    """Forecast ROI for budget recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    forecasts = await toolkit.forecast_roi(
        state.budget_allocations,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "allocation_count": len(state.budget_allocations),
                "forecasts": forecasts,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_FORECAST,
            user_prompt=(f"ROI forecast context:\n{ctx}"),
            schema=ForecastOutput,
        )
        if hasattr(llm_result, "scenarios"):
            logger.info(
                "llm_enhanced",
                node="forecast_roi",
                llm_scenarios=len(llm_result.scenarios),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="forecast_roi",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "forecast_roi",
        f"forecasting {len(state.budget_allocations)} allocations",
        f"generated {len(forecasts)} scenarios",
        elapsed,
        "forecaster",
    )

    return {
        "roi_forecasts": forecasts,
        "stage": SBOStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "forecast_roi",
    }


async def generate_report(
    state: SecurityBudgetOptimizerState,
) -> dict[str, Any]:
    """Generate final budget optimization report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    total_savings = sum(a.get("savings", 0) for a in state.budget_allocations)
    report = {
        "request_id": state.request_id,
        "total_tools": len(state.tools_inventory),
        "total_spend": state.total_spend,
        "avg_roi": state.avg_roi,
        "overlaps_found": len(state.overlap_analyses),
        "total_savings": round(total_savings, 2),
        "forecasts": len(state.roi_forecasts),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "analysis_duration_ms",
        float(duration_ms),
    )
    await toolkit.record_metric(
        "total_savings",
        total_savings,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing analysis {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
