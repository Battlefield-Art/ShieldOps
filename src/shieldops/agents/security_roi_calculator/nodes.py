"""Security ROI Calculator Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    Investment,
    Outcome,
    ReasoningStep,
    ROIResult,
    SRCStage,
)
from .tools import SecurityROICalculatorToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Collect Investments
# ------------------------------------------------------------------


async def collect_investments(
    state: dict[str, Any],
    toolkit: SecurityROICalculatorToolkit,
) -> dict[str, Any]:
    """Collect security investment data."""
    logger.info("src.node.collect_investments")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    investments = await toolkit.collect_investments(tenant_id)
    data = [i.model_dump() for i in investments]

    total = sum(i.annual_cost for i in investments)
    note = f"Collected {len(investments)} investments totaling ${total:,.0f}"

    return {
        "stage": SRCStage.MEASURE_OUTCOMES.value,
        "investments": data,
        "total_investment": round(total, 2),
        "current_step": "collect_investments",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="collect_investments",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Measure Outcomes
# ------------------------------------------------------------------


async def measure_outcomes(
    state: dict[str, Any],
    toolkit: SecurityROICalculatorToolkit,
) -> dict[str, Any]:
    """Measure security outcomes linked to investments."""
    logger.info("src.node.measure_outcomes")
    state = _to_dict(state)

    investments = [Investment(**i) for i in state.get("investments", [])]
    outcomes = await toolkit.measure_outcomes(investments)
    data = [o.model_dump() for o in outcomes]

    total_val = sum(o.value_usd for o in outcomes)
    note = f"Measured {len(outcomes)} outcomes worth ${total_val:,.0f}"

    return {
        "stage": SRCStage.CALCULATE_ROI.value,
        "outcomes": data,
        "current_step": "measure_outcomes",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="measure_outcomes",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Calculate ROI
# ------------------------------------------------------------------


async def calculate_roi(
    state: dict[str, Any],
    toolkit: SecurityROICalculatorToolkit,
) -> dict[str, Any]:
    """Calculate ROI for each investment."""
    logger.info("src.node.calculate_roi")
    state = _to_dict(state)

    investments = [Investment(**i) for i in state.get("investments", [])]
    outcomes = [Outcome(**o) for o in state.get("outcomes", [])]
    results = await toolkit.calculate_roi(investments, outcomes)
    data = [r.model_dump() for r in results]

    avg_roi = round(
        sum(r.roi_pct for r in results) / max(len(results), 1),
        1,
    )
    note = f"Calculated ROI for {len(results)} investments, avg {avg_roi}%"

    try:
        from .prompts import SYSTEM_ROI, ROIInsight

        ctx = json.dumps(
            {
                "results": [
                    {
                        "name": r.investment_name,
                        "cost": r.total_cost,
                        "value": r.total_value,
                        "roi": r.roi_pct,
                        "payback": r.payback_months,
                    }
                    for r in results[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ROIInsight,
            await llm_structured(
                system_prompt=SYSTEM_ROI,
                user_prompt=f"ROI results:\n{ctx}",
                schema=ROIInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="src",
            node="calculate_roi",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="src",
            node="calculate_roi",
        )

    return {
        "stage": SRCStage.COMPARE_BENCHMARKS.value,
        "roi_results": data,
        "overall_roi_pct": avg_roi,
        "current_step": "calculate_roi",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="calculate_roi",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Compare Benchmarks
# ------------------------------------------------------------------


async def compare_benchmarks(
    state: dict[str, Any],
    toolkit: SecurityROICalculatorToolkit,
) -> dict[str, Any]:
    """Compare spending against industry benchmarks."""
    logger.info("src.node.compare_benchmarks")
    state = _to_dict(state)

    investments = [Investment(**i) for i in state.get("investments", [])]
    benchmarks = await toolkit.compare_benchmarks(investments)
    data = [b.model_dump() for b in benchmarks]

    on_track = sum(1 for b in benchmarks if b.recommendation == "on track")
    note = f"Benchmarked {len(benchmarks)} categories, {on_track} on track"

    return {
        "stage": SRCStage.FORECAST.value,
        "benchmarks": data,
        "current_step": "compare_benchmarks",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="compare_benchmarks",
                detail=note,
                confidence=0.8,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Forecast
# ------------------------------------------------------------------


async def forecast_value(
    state: dict[str, Any],
    toolkit: SecurityROICalculatorToolkit,
) -> dict[str, Any]:
    """Forecast future value of security investments."""
    logger.info("src.node.forecast")
    state = _to_dict(state)

    roi_results = [ROIResult(**r) for r in state.get("roi_results", [])]
    forecasts = await toolkit.forecast_value(roi_results)
    data = [f.model_dump() for f in forecasts]

    last_roi = forecasts[-1].projected_roi_pct if forecasts else 0.0
    note = f"Forecasted {len(forecasts)} periods, projected ROI {last_roi}%"

    return {
        "stage": SRCStage.REPORT.value,
        "forecasts": data,
        "current_step": "forecast",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="forecast",
                detail=note,
                confidence=0.75,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: SecurityROICalculatorToolkit,
) -> dict[str, Any]:
    """Compile the final security ROI report."""
    logger.info("src.node.report")
    state = _to_dict(state)

    total_inv = state.get("total_investment", 0.0)
    overall_roi = state.get("overall_roi_pct", 0.0)
    bench_count = len(state.get("benchmarks", []))
    forecast_count = len(state.get("forecasts", []))

    lines = [
        "# Security ROI Report",
        "",
        f"**Total investment:** ${total_inv:,.0f}",
        f"**Overall ROI:** {overall_roi}%",
        f"**Benchmark comparisons:** {bench_count}",
        f"**Forecast periods:** {forecast_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_investment": total_inv,
                "overall_roi": overall_roi,
                "benchmarks": bench_count,
                "forecasts": forecast_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"ROI report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="src",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="src",
            node="report",
        )

    return {
        "stage": SRCStage.REPORT.value,
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
