"""Node implementations for the Cost Anomaly Detector Agent LangGraph workflow."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.cost_anomaly.models import (
    CostAnomalyState,
    DetectorStage,
    ReasoningStep,
)
from shieldops.agents.cost_anomaly.prompts import (
    SYSTEM_CLASSIFY_WASTE,
    SYSTEM_DETECT_ANOMALIES,
    SYSTEM_RECOMMEND,
    SYSTEM_REPORT,
    AnomalyAnalysisOutput,
    RecommendationOutput,
    ReportOutput,
    WasteClassificationOutput,
)
from shieldops.agents.cost_anomaly.tools import CostAnomalyToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CostAnomalyToolkit | None = None


def set_toolkit(toolkit: CostAnomalyToolkit) -> None:
    """Set the shared toolkit instance for all nodes."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> CostAnomalyToolkit:
    if _toolkit is None:
        return CostAnomalyToolkit()
    return _toolkit


# ---------------------------------------------------------------------------
# Node 1: collect_billing
# ---------------------------------------------------------------------------


async def collect_billing(state: CostAnomalyState) -> dict[str, Any]:
    """Collect billing data from multi-cloud billing APIs."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    cost_data = await toolkit.collect_billing_data(state.tenant_id)

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=f"Collected {len(cost_data)} billing data points for tenant {state.tenant_id}",
        confidence=0.95,
        metadata={"services": list({p.service.value for p in cost_data})},
    )

    return {
        "cost_data": cost_data,
        "stage": DetectorStage.DETECT_ANOMALIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_billing",
        "session_start": start,
    }


# ---------------------------------------------------------------------------
# Node 2: detect_anomalies
# ---------------------------------------------------------------------------


async def detect_anomalies(state: CostAnomalyState) -> dict[str, Any]:
    """Detect cost anomalies via statistical deviation from baselines."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    anomalies = await toolkit.detect_cost_anomalies(state.cost_data)

    llm_summary = f"Detected {len(anomalies)} anomalies"
    try:
        context = json.dumps(
            {
                "data_points": len(state.cost_data),
                "anomalies": [a.model_dump() for a in anomalies[:10]],
            },
            default=str,
        )
        llm_result = cast(
            AnomalyAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_DETECT_ANOMALIES,
                user_prompt=f"Cost anomaly detection context:\n{context}",
                schema=AnomalyAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="detect_anomalies",
            anomaly_count=llm_result.anomaly_count,
        )
        llm_summary = (
            f"Detected {len(anomalies)} anomalies. "
            f"LLM: {llm_result.severity_summary}. {llm_result.reasoning}"
        )
    except Exception:
        logger.warning("llm_fallback", node="detect_anomalies")

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=llm_summary,
        confidence=0.88,
        metadata={
            "anomaly_count": len(anomalies),
            "duration_ms": int((datetime.now(UTC) - start).total_seconds() * 1000),
        },
    )

    return {
        "anomalies": anomalies,
        "stage": DetectorStage.CLASSIFY_WASTE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_anomalies",
    }


# ---------------------------------------------------------------------------
# Node 3: classify_waste
# ---------------------------------------------------------------------------


async def classify_waste(state: CostAnomalyState) -> dict[str, Any]:
    """Classify resource waste — idle, oversized, unused storage."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    waste = await toolkit.classify_waste(state.cost_data)
    total_waste = sum(w.monthly_waste for w in waste)

    llm_summary = f"Classified {len(waste)} waste items, ${total_waste:.2f}/mo"
    try:
        context = json.dumps(
            {
                "waste_items": [w.model_dump() for w in waste[:10]],
                "total_monthly_waste": total_waste,
            },
            default=str,
        )
        llm_result = cast(
            WasteClassificationOutput,
            await llm_structured(
                system_prompt=SYSTEM_CLASSIFY_WASTE,
                user_prompt=f"Waste classification context:\n{context}",
                schema=WasteClassificationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="classify_waste",
            total_waste=llm_result.total_monthly_waste,
        )
        llm_summary = (
            f"Classified {len(waste)} waste items, ${total_waste:.2f}/mo. "
            f"LLM estimate: ${llm_result.total_monthly_waste:.2f}/mo. "
            f"{llm_result.reasoning}"
        )
    except Exception:
        logger.warning("llm_fallback", node="classify_waste")

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=llm_summary,
        confidence=0.82,
        metadata={
            "waste_count": len(waste),
            "total_monthly_waste": round(total_waste, 2),
            "duration_ms": int((datetime.now(UTC) - start).total_seconds() * 1000),
        },
    )

    return {
        "waste_classifications": waste,
        "total_monthly_waste": round(total_waste, 2),
        "stage": DetectorStage.ANALYZE_LLM_COSTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "classify_waste",
    }


# ---------------------------------------------------------------------------
# Node 4: analyze_llm_costs
# ---------------------------------------------------------------------------


async def analyze_llm_costs(state: CostAnomalyState) -> dict[str, Any]:
    """Analyze LLM API costs by model, agent, and operation."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    llm_analysis = await toolkit.analyze_llm_costs(state.tenant_id)

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=(
            f"LLM cost analysis: ${llm_analysis.get('total_daily', 0):.2f}/day, "
            f"budget at {llm_analysis.get('budget_pct', 0):.0f}%, "
            f"overrun={'yes' if llm_analysis.get('overrun_detected') else 'no'}"
        ),
        confidence=0.90,
        metadata={
            "total_daily": llm_analysis.get("total_daily", 0),
            "model_count": len(llm_analysis.get("by_model", {})),
            "duration_ms": int((datetime.now(UTC) - start).total_seconds() * 1000),
        },
    )

    return {
        "llm_cost_analysis": llm_analysis,
        "stage": DetectorStage.RECOMMEND,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_llm_costs",
    }


# ---------------------------------------------------------------------------
# Node 5: recommend
# ---------------------------------------------------------------------------


async def recommend(state: CostAnomalyState) -> dict[str, Any]:
    """Generate actionable cost optimization recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    recs = await toolkit.generate_recommendations(
        state.anomalies,
        state.waste_classifications,
    )
    total_savings = sum(r.estimated_savings for r in recs)

    llm_summary = f"Generated {len(recs)} recommendations, savings ${total_savings:.2f}/mo"
    try:
        context = json.dumps(
            {
                "anomalies": [a.model_dump() for a in state.anomalies[:10]],
                "waste": [w.model_dump() for w in state.waste_classifications[:10]],
                "llm_costs": state.llm_cost_analysis,
                "recommendations": [r.model_dump() for r in recs[:10]],
            },
            default=str,
        )
        llm_result = cast(
            RecommendationOutput,
            await llm_structured(
                system_prompt=SYSTEM_RECOMMEND,
                user_prompt=f"Cost recommendation context:\n{context}",
                schema=RecommendationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="recommend",
            savings=llm_result.total_savings_potential,
        )
        llm_summary = (
            f"Generated {len(recs)} recommendations, savings ${total_savings:.2f}/mo. "
            f"LLM savings estimate: ${llm_result.total_savings_potential:.2f}/mo. "
            f"Quick wins: {len(llm_result.quick_wins)}. {llm_result.reasoning}"
        )
    except Exception:
        logger.warning("llm_fallback", node="recommend")

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=llm_summary,
        confidence=0.85,
        metadata={
            "recommendation_count": len(recs),
            "total_savings": round(total_savings, 2),
            "duration_ms": int((datetime.now(UTC) - start).total_seconds() * 1000),
        },
    )

    return {
        "recommendations": recs,
        "stage": DetectorStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend",
    }


# ---------------------------------------------------------------------------
# Node 6: generate_report
# ---------------------------------------------------------------------------


async def generate_report(state: CostAnomalyState) -> dict[str, Any]:
    """Generate the final cost anomaly report with stats."""
    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    total_savings = sum(r.estimated_savings for r in state.recommendations)
    auto_count = sum(1 for r in state.recommendations if r.auto_executable)

    stats: dict[str, Any] = {
        "billing_data_points": len(state.cost_data),
        "anomalies_detected": len(state.anomalies),
        "waste_items": len(state.waste_classifications),
        "total_monthly_waste": state.total_monthly_waste,
        "recommendations": len(state.recommendations),
        "total_savings_potential": round(total_savings, 2),
        "auto_executable_count": auto_count,
        "llm_overrun": state.llm_cost_analysis.get("overrun_detected", False),
        "duration_ms": duration_ms,
    }

    report_summary = (
        f"Analysis complete: {len(state.anomalies)} anomalies, "
        f"{len(state.waste_classifications)} waste items, "
        f"${total_savings:.2f}/mo savings potential"
    )
    try:
        context = json.dumps(
            {
                "stats": stats,
                "anomalies": [a.model_dump() for a in state.anomalies[:5]],
                "waste": [w.model_dump() for w in state.waste_classifications[:5]],
                "llm_costs": state.llm_cost_analysis,
                "recommendations": [r.model_dump() for r in state.recommendations[:5]],
            },
            default=str,
        )
        llm_result = cast(
            ReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Generate executive cost anomaly report:\n{context}",
                schema=ReportOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="generate_report",
            risk_level=llm_result.risk_level,
        )
        stats["executive_summary"] = llm_result.executive_summary
        stats["risk_level"] = llm_result.risk_level
        stats["key_findings"] = llm_result.key_findings
        report_summary = (
            f"{llm_result.executive_summary} Risk: {llm_result.risk_level}. {llm_result.reasoning}"
        )
    except Exception:
        logger.warning("llm_fallback", node="generate_report")
        stats["executive_summary"] = report_summary
        stats["risk_level"] = "medium"
        stats["key_findings"] = [
            f"{len(state.anomalies)} cost anomalies detected",
            f"${state.total_monthly_waste:.2f}/mo in resource waste",
            f"${total_savings:.2f}/mo savings potential identified",
        ]

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=report_summary,
        confidence=0.90,
        metadata={"duration_ms": duration_ms},
    )

    return {
        "stats": stats,
        "stage": DetectorStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
        "session_duration_ms": duration_ms,
    }
