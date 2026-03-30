"""Cloud Cost Optimizer Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    BillingRecord,
    CCOStage,
    ReasoningStep,
    SavingsRecommendation,
    SpendingAnalysis,
    WasteItem,
)
from .tools import CloudCostOptimizerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Collect Billing
# ------------------------------------------------------------------


async def collect_billing(
    state: dict[str, Any],
    toolkit: CloudCostOptimizerToolkit,
) -> dict[str, Any]:
    """Collect billing records from cloud providers."""
    logger.info("cco.node.collect_billing")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    records = await toolkit.collect_billing(tenant_id)
    data = [r.model_dump() for r in records]

    total = sum(r.monthly_cost for r in records)
    note = f"Collected {len(records)} billing records, ${total:,.2f}/mo total"

    return {
        "stage": CCOStage.ANALYZE_SPENDING.value,
        "billing_records": data,
        "total_monthly_spend": round(total, 2),
        "current_step": "collect_billing",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="collect_billing",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Analyze Spending
# ------------------------------------------------------------------


async def analyze_spending(
    state: dict[str, Any],
    toolkit: CloudCostOptimizerToolkit,
) -> dict[str, Any]:
    """Analyze spending patterns by category."""
    logger.info("cco.node.analyze_spending")
    state = _to_dict(state)

    records = [BillingRecord(**r) for r in state.get("billing_records", [])]
    analysis = await toolkit.analyze_spending(records)
    data = [a.model_dump() for a in analysis]

    note = f"Analyzed {len(analysis)} cost categories"

    try:
        from .prompts import SYSTEM_ANALYZE, SpendingInsight

        ctx = json.dumps(
            {
                "categories": [
                    {
                        "category": a.category.value,
                        "monthly": a.total_monthly,
                        "trend": a.trend,
                        "budget_pct": a.budget_pct,
                    }
                    for a in analysis[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            SpendingInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Spending analysis:\n{ctx}",
                schema=SpendingInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cco",
            node="analyze_spending",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cco",
            node="analyze_spending",
        )

    return {
        "stage": CCOStage.IDENTIFY_WASTE.value,
        "spending_analysis": data,
        "current_step": "analyze_spending",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="analyze_spending",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Identify Waste
# ------------------------------------------------------------------


async def identify_waste(
    state: dict[str, Any],
    toolkit: CloudCostOptimizerToolkit,
) -> dict[str, Any]:
    """Identify wasted cloud resources."""
    logger.info("cco.node.identify_waste")
    state = _to_dict(state)

    records = [BillingRecord(**r) for r in state.get("billing_records", [])]
    waste = await toolkit.identify_waste(records)
    data = [w.model_dump() for w in waste]

    total_waste = sum(w.monthly_waste for w in waste)
    note = f"Found {len(waste)} waste items, ${total_waste:,.2f}/mo potential"

    return {
        "stage": CCOStage.RECOMMEND_SAVINGS.value,
        "waste_items": data,
        "current_step": "identify_waste",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="identify_waste",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Recommend Savings
# ------------------------------------------------------------------


async def recommend_savings(
    state: dict[str, Any],
    toolkit: CloudCostOptimizerToolkit,
) -> dict[str, Any]:
    """Generate savings recommendations."""
    logger.info("cco.node.recommend_savings")
    state = _to_dict(state)

    waste = [WasteItem(**w) for w in state.get("waste_items", [])]
    analysis = [SpendingAnalysis(**a) for a in state.get("spending_analysis", [])]
    recs = await toolkit.recommend_savings(waste, analysis)
    data = [r.model_dump() for r in recs]

    total_savings = sum(r.estimated_monthly_savings for r in recs)
    note = f"Generated {len(recs)} recommendations, ${total_savings:,.2f}/mo savings"

    return {
        "stage": CCOStage.IMPLEMENT_OPTIMIZATIONS.value,
        "recommendations": data,
        "total_savings_potential": round(
            total_savings,
            2,
        ),
        "current_step": "recommend_savings",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="recommend_savings",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Implement Optimizations
# ------------------------------------------------------------------


async def implement_optimizations(
    state: dict[str, Any],
    toolkit: CloudCostOptimizerToolkit,
) -> dict[str, Any]:
    """Implement approved optimizations."""
    logger.info("cco.node.implement_optimizations")
    state = _to_dict(state)

    recs = [SavingsRecommendation(**r) for r in state.get("recommendations", [])]
    results = await toolkit.implement_optimizations(recs)
    data = [o.model_dump() for o in results]

    applied = sum(1 for o in results if o.status == "applied")
    note = f"Implemented {applied}/{len(results)} optimizations"

    return {
        "stage": CCOStage.REPORT.value,
        "optimizations": data,
        "current_step": "implement_optimizations",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="implement_optimizations",
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
    toolkit: CloudCostOptimizerToolkit,
) -> dict[str, Any]:
    """Compile the final cost optimization report."""
    logger.info("cco.node.report")
    state = _to_dict(state)

    total_spend = state.get("total_monthly_spend", 0.0)
    total_savings = state.get(
        "total_savings_potential",
        0.0,
    )
    waste_count = len(state.get("waste_items", []))
    rec_count = len(state.get("recommendations", []))
    opt_count = len(state.get("optimizations", []))

    lines = [
        "# Cloud Cost Optimization Report",
        "",
        f"**Total monthly spend:** ${total_spend:,.2f}",
        f"**Savings potential:** ${total_savings:,.2f}",
        f"**Waste items:** {waste_count}",
        f"**Recommendations:** {rec_count}",
        f"**Optimizations applied:** {opt_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_spend": total_spend,
                "total_savings": total_savings,
                "waste_count": waste_count,
                "rec_count": rec_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Cost optimization report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cco",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cco",
            node="report",
        )

    return {
        "stage": CCOStage.REPORT.value,
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
