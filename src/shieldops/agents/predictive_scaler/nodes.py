"""Predictive Scaler Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    DemandPattern,
    DemandPrediction,
    MetricSnapshot,
    PSStage,
    ReasoningStep,
    ScalingPlan,
)
from .tools import PredictiveScalerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Collect Metrics
# ------------------------------------------------------------------


async def collect_metrics(
    state: dict[str, Any],
    toolkit: PredictiveScalerToolkit,
) -> dict[str, Any]:
    """Collect resource utilization metrics."""
    logger.info("ps.node.collect_metrics")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    snapshots = await toolkit.collect_metrics(tenant_id)
    data = [s.model_dump() for s in snapshots]

    note = (
        f"Collected {len(snapshots)} metric snapshots "
        f"across {len(set(s.region for s in snapshots))} regions"
    )

    return {
        "stage": PSStage.ANALYZE_PATTERNS.value,
        "metrics": data,
        "total_resources_monitored": len(snapshots),
        "current_step": "collect_metrics",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="collect_metrics",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Analyze Patterns
# ------------------------------------------------------------------


async def analyze_patterns(
    state: dict[str, Any],
    toolkit: PredictiveScalerToolkit,
) -> dict[str, Any]:
    """Analyze demand patterns from metric history."""
    logger.info("ps.node.analyze_patterns")
    state = _to_dict(state)

    metrics = [MetricSnapshot(**m) for m in state.get("metrics", [])]
    patterns = await toolkit.analyze_patterns(metrics)
    data = [p.model_dump() for p in patterns]

    increasing = sum(1 for p in patterns if p.trend == "increasing")
    note = f"Detected {len(patterns)} patterns, {increasing} with increasing trend"

    try:
        from .prompts import (
            SYSTEM_ANALYZE_PATTERNS,
            PatternInsight,
        )

        ctx = json.dumps(
            {
                "patterns": [
                    {
                        "resource": p.resource_id,
                        "type": p.pattern_type,
                        "trend": p.trend,
                        "peak_util": p.peak_utilization,
                        "confidence": p.confidence,
                    }
                    for p in patterns[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PatternInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE_PATTERNS,
                user_prompt=(f"Demand pattern analysis:\n{ctx}"),
                schema=PatternInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ps",
            node="analyze_patterns",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ps",
            node="analyze_patterns",
        )

    return {
        "stage": PSStage.PREDICT_DEMAND.value,
        "patterns": data,
        "current_step": "analyze_patterns",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="analyze_patterns",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Predict Demand
# ------------------------------------------------------------------


async def predict_demand(
    state: dict[str, Any],
    toolkit: PredictiveScalerToolkit,
) -> dict[str, Any]:
    """Predict future resource demand."""
    logger.info("ps.node.predict_demand")
    state = _to_dict(state)

    patterns = [DemandPattern(**p) for p in state.get("patterns", [])]
    predictions = await toolkit.predict_demand(patterns)
    data = [p.model_dump() for p in predictions]

    breaches = sum(1 for p in predictions if p.breach_threshold)
    note = f"Generated {len(predictions)} predictions, {breaches} threshold breaches expected"

    try:
        from .prompts import (
            SYSTEM_PREDICT_DEMAND,
            PredictionInsight,
        )

        ctx = json.dumps(
            {
                "predictions": [
                    {
                        "resource": p.resource_id,
                        "cpu": p.predicted_cpu_pct,
                        "mem": p.predicted_memory_pct,
                        "breach": p.breach_threshold,
                        "direction": p.recommended_direction,
                    }
                    for p in predictions[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PredictionInsight,
            await llm_structured(
                system_prompt=SYSTEM_PREDICT_DEMAND,
                user_prompt=(f"Demand predictions:\n{ctx}"),
                schema=PredictionInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ps",
            node="predict_demand",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ps",
            node="predict_demand",
        )

    return {
        "stage": PSStage.PLAN_SCALING.value,
        "predictions": data,
        "current_step": "predict_demand",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="predict_demand",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Plan Scaling
# ------------------------------------------------------------------


async def plan_scaling(
    state: dict[str, Any],
    toolkit: PredictiveScalerToolkit,
) -> dict[str, Any]:
    """Create scaling plans from predictions."""
    logger.info("ps.node.plan_scaling")
    state = _to_dict(state)

    predictions = [DemandPrediction(**p) for p in state.get("predictions", [])]
    plans = await toolkit.plan_scaling(predictions)
    data = [p.model_dump() for p in plans]

    cost_delta = sum(p.estimated_cost_delta for p in plans)
    note = f"Created {len(plans)} scaling plans, est. cost delta ${cost_delta:,.2f}/mo"

    try:
        from .prompts import (
            SYSTEM_PLAN_SCALING,
            ScalingInsight,
        )

        ctx = json.dumps(
            {
                "plans": [
                    {
                        "resource": p.resource_id,
                        "direction": p.direction,
                        "current": p.current_capacity,
                        "target": p.target_capacity,
                        "cost_delta": p.estimated_cost_delta,
                    }
                    for p in plans[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ScalingInsight,
            await llm_structured(
                system_prompt=SYSTEM_PLAN_SCALING,
                user_prompt=(f"Scaling plans:\n{ctx}"),
                schema=ScalingInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ps",
            node="plan_scaling",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ps",
            node="plan_scaling",
        )

    return {
        "stage": PSStage.EXECUTE_SCALING.value,
        "scaling_plans": data,
        "current_step": "plan_scaling",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="plan_scaling",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Execute Scaling
# ------------------------------------------------------------------


async def execute_scaling(
    state: dict[str, Any],
    toolkit: PredictiveScalerToolkit,
) -> dict[str, Any]:
    """Execute approved scaling plans."""
    logger.info("ps.node.execute_scaling")
    state = _to_dict(state)

    plans = [ScalingPlan(**p) for p in state.get("scaling_plans", [])]
    results = await toolkit.execute_scaling(plans)
    data = [r.model_dump() for r in results]

    applied = sum(1 for r in results if r.status == "applied")
    note = f"Executed {applied}/{len(results)} scaling actions"

    return {
        "stage": PSStage.REPORT.value,
        "executions": data,
        "total_scaling_actions": applied,
        "current_step": "execute_scaling",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="execute_scaling",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: PredictiveScalerToolkit,
) -> dict[str, Any]:
    """Compile the final predictive scaling report."""
    logger.info("ps.node.report")
    state = _to_dict(state)

    monitored = state.get("total_resources_monitored", 0)
    actions = state.get("total_scaling_actions", 0)
    plan_count = len(state.get("scaling_plans", []))
    pred_count = len(state.get("predictions", []))

    breaches = sum(1 for p in state.get("predictions", []) if p.get("breach_threshold", False))

    lines = [
        "# Predictive Scaling Report",
        "",
        f"**Resources monitored:** {monitored}",
        f"**Predictions generated:** {pred_count}",
        f"**Threshold breaches predicted:** {breaches}",
        f"**Scaling plans created:** {plan_count}",
        f"**Scaling actions executed:** {actions}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "monitored": monitored,
                "predictions": pred_count,
                "breaches": breaches,
                "plans": plan_count,
                "actions": actions,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Predictive scaling report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ps",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ps",
            node="report",
        )

    return {
        "stage": PSStage.REPORT.value,
        "report": report_text,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
