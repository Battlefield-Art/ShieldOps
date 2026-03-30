"""Observability Pipeline Optimizer Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    OPOStage,
    PipelineAudit,
    ReasoningStep,
)
from .tools import ObservabilityPipelineOptimizerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Audit Pipelines
# ------------------------------------------------------------------


async def audit_pipelines(
    state: dict[str, Any],
    toolkit: ObservabilityPipelineOptimizerToolkit,
) -> dict[str, Any]:
    """Audit all observability pipelines."""
    logger.info("opo.node.audit_pipelines")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    audits = await toolkit.audit_pipelines(tenant_id)
    data = [a.model_dump() for a in audits]

    total_cost = sum(a.monthly_cost for a in audits)
    total_gb = sum(a.ingestion_rate_gb_day for a in audits)
    note = (
        f"Audited {len(audits)} pipelines, ${total_cost:,.2f}/mo, {total_gb:.1f} GB/day ingestion"
    )

    return {
        "stage": OPOStage.ANALYZE_CARDINALITY.value,
        "pipeline_audits": data,
        "total_monthly_cost": round(total_cost, 2),
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="audit_pipelines",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Analyze Cardinality
# ------------------------------------------------------------------


async def analyze_cardinality(
    state: dict[str, Any],
    toolkit: ObservabilityPipelineOptimizerToolkit,
) -> dict[str, Any]:
    """Analyze metric cardinality across pipelines."""
    logger.info("opo.node.analyze_cardinality")
    state = _to_dict(state)

    audits = [PipelineAudit(**a) for a in state.get("pipeline_audits", [])]
    analyses = await toolkit.analyze_cardinality(audits)
    data = [a.model_dump() for a in analyses]

    total_series = sum(a.unique_series for a in analyses)
    critical = sum(1 for a in analyses if a.explosion_risk == "critical")
    note = (
        f"Analyzed {len(analyses)} metrics, "
        f"{total_series:,} total series, "
        f"{critical} critical risks"
    )

    try:
        from .prompts import (
            SYSTEM_CARDINALITY,
            CardinalityInsight,
        )

        ctx = json.dumps(
            {
                "metrics": [
                    {
                        "name": a.metric_name,
                        "series": a.unique_series,
                        "risk": a.explosion_risk,
                        "labels": a.label_count,
                    }
                    for a in analyses[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            CardinalityInsight,
            await llm_structured(
                system_prompt=SYSTEM_CARDINALITY,
                user_prompt=(f"Cardinality analysis:\n{ctx}"),
                schema=CardinalityInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="opo",
            node="analyze_cardinality",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="opo",
            node="analyze_cardinality",
        )

    return {
        "stage": OPOStage.OPTIMIZE_SAMPLING.value,
        "cardinality_analyses": data,
        "total_cardinality_reduced": total_series,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="analyze_cardinality",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Optimize Sampling
# ------------------------------------------------------------------


async def optimize_sampling(
    state: dict[str, Any],
    toolkit: ObservabilityPipelineOptimizerToolkit,
) -> dict[str, Any]:
    """Optimize sampling configurations."""
    logger.info("opo.node.optimize_sampling")
    state = _to_dict(state)

    audits = [PipelineAudit(**a) for a in state.get("pipeline_audits", [])]
    configs = await toolkit.optimize_sampling(audits)
    data = [c.model_dump() for c in configs]

    avg_savings = sum(c.estimated_savings_pct for c in configs) / max(len(configs), 1)
    note = f"Generated {len(configs)} sampling configs, avg {avg_savings:.1f}% savings"

    try:
        from .prompts import (
            SYSTEM_SAMPLING,
            SamplingInsight,
        )

        ctx = json.dumps(
            {
                "configs": [
                    {
                        "pipeline": c.pipeline_type.value,
                        "strategy": c.strategy,
                        "rate": c.recommended_rate,
                        "savings_pct": (c.estimated_savings_pct),
                    }
                    for c in configs[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            SamplingInsight,
            await llm_structured(
                system_prompt=SYSTEM_SAMPLING,
                user_prompt=(f"Sampling optimization:\n{ctx}"),
                schema=SamplingInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="opo",
            node="optimize_sampling",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="opo",
            node="optimize_sampling",
        )

    return {
        "stage": OPOStage.REDUCE_COSTS.value,
        "sampling_configs": data,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="optimize_sampling",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Reduce Costs
# ------------------------------------------------------------------


async def reduce_costs(
    state: dict[str, Any],
    toolkit: ObservabilityPipelineOptimizerToolkit,
) -> dict[str, Any]:
    """Identify and apply cost reductions."""
    logger.info("opo.node.reduce_costs")
    state = _to_dict(state)

    audits = [PipelineAudit(**a) for a in state.get("pipeline_audits", [])]
    from .models import CardinalityAnalysis, SamplingConfig

    cardinality = [CardinalityAnalysis(**c) for c in state.get("cardinality_analyses", [])]
    sampling = [SamplingConfig(**s) for s in state.get("sampling_configs", [])]

    reductions = await toolkit.reduce_costs(audits, cardinality, sampling)
    data = [r.model_dump() for r in reductions]

    total_savings = sum(r.monthly_savings for r in reductions)
    note = f"Found {len(reductions)} cost reductions, ${total_savings:,.2f}/mo potential savings"

    try:
        from .prompts import SYSTEM_COST, CostInsight

        ctx = json.dumps(
            {
                "reductions": [
                    {
                        "action": r.action.value,
                        "savings": r.monthly_savings,
                        "risk": r.risk,
                        "auto": r.auto_applicable,
                    }
                    for r in reductions[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            CostInsight,
            await llm_structured(
                system_prompt=SYSTEM_COST,
                user_prompt=(f"Cost reduction analysis:\n{ctx}"),
                schema=CostInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="opo",
            node="reduce_costs",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="opo",
            node="reduce_costs",
        )

    return {
        "stage": OPOStage.VALIDATE_QUALITY.value,
        "cost_reductions": data,
        "total_monthly_savings": round(total_savings, 2),
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="reduce_costs",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Validate Quality
# ------------------------------------------------------------------


async def validate_quality(
    state: dict[str, Any],
    toolkit: ObservabilityPipelineOptimizerToolkit,
) -> dict[str, Any]:
    """Validate signal quality after optimizations."""
    logger.info("opo.node.validate_quality")
    state = _to_dict(state)

    audits = [PipelineAudit(**a) for a in state.get("pipeline_audits", [])]
    from .models import SamplingConfig

    sampling = [SamplingConfig(**s) for s in state.get("sampling_configs", [])]

    validations = await toolkit.validate_quality(audits, sampling)
    data = [v.model_dump() for v in validations]

    passed = sum(1 for v in validations if v.within_threshold)
    total = len(validations)
    note = f"Validated {total} quality metrics, {passed}/{total} within threshold"

    return {
        "stage": OPOStage.REPORT.value,
        "quality_validations": data,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="validate_quality",
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
    toolkit: ObservabilityPipelineOptimizerToolkit,
) -> dict[str, Any]:
    """Compile the final pipeline optimization report."""
    logger.info("opo.node.report")
    state = _to_dict(state)

    total_cost = state.get("total_monthly_cost", 0.0)
    total_savings = state.get("total_monthly_savings", 0.0)
    pipeline_count = len(state.get("pipeline_audits", []))
    cardinality_count = len(state.get("cardinality_analyses", []))
    reduction_count = len(state.get("cost_reductions", []))
    quality_checks = state.get("quality_validations", [])
    passed = sum(1 for v in quality_checks if v.get("within_threshold", False))

    lines = [
        "# Observability Pipeline Optimization Report",
        "",
        f"**Pipelines audited:** {pipeline_count}",
        f"**Total monthly cost:** ${total_cost:,.2f}",
        f"**Total savings:** ${total_savings:,.2f}",
        f"**Cardinality hotspots:** {cardinality_count}",
        f"**Cost reductions:** {reduction_count}",
        f"**Quality checks passed:** {passed}/{len(quality_checks)}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_cost": total_cost,
                "total_savings": total_savings,
                "pipelines": pipeline_count,
                "cardinality_hotspots": cardinality_count,
                "reductions": reduction_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Pipeline optimization report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="opo",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="opo",
            node="report",
        )

    return {
        "stage": OPOStage.REPORT.value,
        "report": report_text,
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
