"""Capacity Planner Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    Bottleneck,
    CapacityRisk,
    CapacityStage,
    DemandForecast,
    ReasoningStep,
    ResourceMetric,
    ScalingPlan,
)
from .tools import CapacityPlannerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Node 1: Collect Metrics
# ---------------------------------------------------------------------------


async def collect_metrics(state: dict[str, Any], toolkit: CapacityPlannerToolkit) -> dict[str, Any]:
    """Collect current resource utilisation metrics for the tenant."""
    logger.info("capacity_planner.node.collect_metrics")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    metrics = await toolkit.collect_resource_metrics(tenant_id)
    metrics_data = [m.model_dump() for m in metrics]

    reasoning_note = f"Collected {len(metrics)} resource metrics for tenant '{tenant_id}'"

    try:
        from .prompts import SYSTEM_COLLECT, MetricsAnalysisResult

        ctx = json.dumps(
            {
                "total_metrics": len(metrics),
                "resources": [
                    {
                        "resource_id": m.resource_id,
                        "type": m.resource_type.value,
                        "usage_pct": m.current_usage_pct,
                        "trend": m.trend,
                        "days_to_exhaustion": m.days_to_exhaustion,
                    }
                    for m in metrics[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            MetricsAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_COLLECT,
                user_prompt=f"Resource metrics:\n{ctx}",
                schema=MetricsAnalysisResult,
            ),
        )
        logger.info("llm_enhanced", agent="capacity_planner", node="collect_metrics")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="capacity_planner", node="collect_metrics")

    return {
        "stage": CapacityStage.FORECAST_DEMAND.value,
        "metrics": metrics_data,
        "total_resources": len(metrics),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="collect_metrics",
                detail=reasoning_note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ---------------------------------------------------------------------------
# Node 2: Forecast Demand
# ---------------------------------------------------------------------------


async def forecast_demand(state: dict[str, Any], toolkit: CapacityPlannerToolkit) -> dict[str, Any]:
    """Forecast future resource demand based on collected metrics."""
    logger.info("capacity_planner.node.forecast_demand")
    state = _to_dict(state)

    raw_metrics = state.get("metrics", [])
    metrics = [ResourceMetric(**m) for m in raw_metrics]

    forecasts = await toolkit.forecast_demand(metrics)
    forecasts_data = [f.model_dump() for f in forecasts]

    reasoning_note = f"Generated {len(forecasts)} demand forecasts"

    try:
        from .prompts import SYSTEM_FORECAST, ForecastInsight

        ctx = json.dumps(
            {
                "forecasts": [
                    {
                        "resource_id": f.resource_id,
                        "forecasted_pct": f.forecasted_usage_pct,
                        "confidence": f.confidence,
                        "seasonal_pattern": f.seasonal_pattern,
                    }
                    for f in forecasts[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ForecastInsight,
            await llm_structured(
                system_prompt=SYSTEM_FORECAST,
                user_prompt=f"Demand forecasts:\n{ctx}",
                schema=ForecastInsight,
            ),
        )
        logger.info("llm_enhanced", agent="capacity_planner", node="forecast_demand")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="capacity_planner", node="forecast_demand")

    return {
        "stage": CapacityStage.IDENTIFY_BOTTLENECKS.value,
        "forecasts": forecasts_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="forecast_demand",
                detail=reasoning_note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ---------------------------------------------------------------------------
# Node 3: Identify Bottlenecks
# ---------------------------------------------------------------------------


async def identify_bottlenecks(
    state: dict[str, Any], toolkit: CapacityPlannerToolkit
) -> dict[str, Any]:
    """Identify resource bottlenecks from metrics and forecasts."""
    logger.info("capacity_planner.node.identify_bottlenecks")
    state = _to_dict(state)

    raw_metrics = state.get("metrics", [])
    raw_forecasts = state.get("forecasts", [])
    metrics = [ResourceMetric(**m) for m in raw_metrics]
    forecasts = [DemandForecast(**f) for f in raw_forecasts]

    bottlenecks = await toolkit.identify_bottlenecks(metrics, forecasts)
    bottlenecks_data = [b.model_dump() for b in bottlenecks]

    critical = sum(1 for b in bottlenecks if b.severity == CapacityRisk.CRITICAL)

    reasoning_note = f"Identified {len(bottlenecks)} bottlenecks ({critical} critical)"

    try:
        from .prompts import SYSTEM_BOTTLENECK, BottleneckAssessment

        ctx = json.dumps(
            {
                "bottleneck_count": len(bottlenecks),
                "critical_count": critical,
                "bottlenecks": [
                    {
                        "resource_id": b.resource_id,
                        "type": b.resource_type.value,
                        "severity": b.severity.value,
                        "description": b.description,
                    }
                    for b in bottlenecks[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            BottleneckAssessment,
            await llm_structured(
                system_prompt=SYSTEM_BOTTLENECK,
                user_prompt=f"Bottleneck analysis:\n{ctx}",
                schema=BottleneckAssessment,
            ),
        )
        logger.info("llm_enhanced", agent="capacity_planner", node="identify_bottlenecks")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="capacity_planner", node="identify_bottlenecks")

    return {
        "stage": CapacityStage.PLAN_SCALING.value,
        "bottlenecks": bottlenecks_data,
        "critical_count": critical,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="identify_bottlenecks",
                detail=reasoning_note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ---------------------------------------------------------------------------
# Node 4: Plan Scaling
# ---------------------------------------------------------------------------


async def plan_scaling(state: dict[str, Any], toolkit: CapacityPlannerToolkit) -> dict[str, Any]:
    """Generate scaling plans for identified bottlenecks."""
    logger.info("capacity_planner.node.plan_scaling")
    state = _to_dict(state)

    raw_bottlenecks = state.get("bottlenecks", [])
    raw_metrics = state.get("metrics", [])
    bottlenecks = [Bottleneck(**b) for b in raw_bottlenecks]
    metrics = [ResourceMetric(**m) for m in raw_metrics]

    plans = await toolkit.plan_scaling(bottlenecks, metrics)
    plans_data = [p.model_dump() for p in plans]

    total_cost = sum(p.estimated_cost_delta for p in plans)

    reasoning_note = (
        f"Created {len(plans)} scaling plans, estimated cost delta: ${total_cost:,.2f}/mo"
    )

    try:
        from .prompts import SYSTEM_SCALING, ScalingRecommendation

        ctx = json.dumps(
            {
                "plan_count": len(plans),
                "total_cost_delta": total_cost,
                "plans": [
                    {
                        "resource_id": p.resource_id,
                        "action": p.action,
                        "current": p.current_capacity,
                        "recommended": p.recommended_capacity,
                        "cost_delta": p.estimated_cost_delta,
                        "auto_scalable": p.auto_scalable,
                    }
                    for p in plans[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ScalingRecommendation,
            await llm_structured(
                system_prompt=SYSTEM_SCALING,
                user_prompt=f"Scaling plans:\n{ctx}",
                schema=ScalingRecommendation,
            ),
        )
        logger.info("llm_enhanced", agent="capacity_planner", node="plan_scaling")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="capacity_planner", node="plan_scaling")

    return {
        "stage": CapacityStage.RECOMMEND.value,
        "scaling_plans": plans_data,
        "estimated_monthly_cost_delta": round(total_cost, 2),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="plan_scaling",
                detail=reasoning_note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ---------------------------------------------------------------------------
# Node 5: Recommend
# ---------------------------------------------------------------------------


async def recommend(state: dict[str, Any], toolkit: CapacityPlannerToolkit) -> dict[str, Any]:
    """Distil scaling plans into prioritised recommendations."""
    logger.info("capacity_planner.node.recommend")
    state = _to_dict(state)

    raw_plans = state.get("scaling_plans", [])
    plans = [ScalingPlan(**p) for p in raw_plans]
    bottlenecks = [Bottleneck(**b) for b in state.get("bottlenecks", [])]

    recommendations: list[str] = []
    for plan in plans:
        recommendations.append(
            f"[{plan.action}] {plan.resource_id}: "
            f"{plan.current_capacity} -> {plan.recommended_capacity} "
            f"(+${plan.estimated_cost_delta:,.2f}/mo"
            f"{', auto-scalable' if plan.auto_scalable else ', manual'})"
        )

    for btl in bottlenecks:
        if btl.severity == CapacityRisk.CRITICAL:
            recommendations.insert(
                0,
                f"URGENT: {btl.description} — {btl.mitigation}",
            )

    return {
        "stage": CapacityStage.REPORT.value,
        "recommendations": recommendations,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="recommend",
                detail=f"Produced {len(recommendations)} recommendations",
                confidence=0.9,
            ).model_dump()
        ],
    }


# ---------------------------------------------------------------------------
# Node 6: Report
# ---------------------------------------------------------------------------


async def generate_report(state: dict[str, Any], toolkit: CapacityPlannerToolkit) -> dict[str, Any]:
    """Compile the final capacity planning report."""
    logger.info("capacity_planner.node.generate_report")
    state = _to_dict(state)

    metrics_count = len(state.get("metrics", []))
    bottlenecks_count = len(state.get("bottlenecks", []))
    plans_count = len(state.get("scaling_plans", []))
    critical = state.get("critical_count", 0)
    cost_delta = state.get("estimated_monthly_cost_delta", 0.0)
    recommendations = state.get("recommendations", [])

    lines = [
        "# Capacity Planning Report",
        "",
        f"**Resources analysed:** {metrics_count}",
        f"**Bottlenecks found:** {bottlenecks_count} ({critical} critical)",
        f"**Scaling plans:** {plans_count}",
        f"**Estimated monthly cost delta:** ${cost_delta:,.2f}",
        "",
        "## Recommendations",
    ]
    for i, rec in enumerate(recommendations, 1):
        lines.append(f"{i}. {rec}")

    report = "\n".join(lines)

    return {
        "stage": CapacityStage.REPORT.value,
        "report": report,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="generate_report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
