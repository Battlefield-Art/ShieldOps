"""FinOps Forecaster Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    FFStage,
    ReasoningStep,
    SpendForecast,
    SpendHistory,
    TrendAnalysis,
)
from .tools import FinopsForecasterToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ----------------------------------------------------------
# Node 1: Collect History
# ----------------------------------------------------------


async def collect_history(
    state: dict[str, Any],
    toolkit: FinopsForecasterToolkit,
) -> dict[str, Any]:
    """Collect 12 months of spending history."""
    logger.info("ff.node.collect_history")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    records = await toolkit.collect_history(tenant_id)
    data = [r.model_dump() for r in records]

    total = sum(r.amount for r in records)
    note = f"Collected {len(records)} spend records, ${total:,.2f} total over 12 months"

    return {
        "stage": FFStage.ANALYZE_TRENDS.value,
        "spend_history": data,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="collect_history",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ----------------------------------------------------------
# Node 2: Analyze Trends
# ----------------------------------------------------------


async def analyze_trends(
    state: dict[str, Any],
    toolkit: FinopsForecasterToolkit,
) -> dict[str, Any]:
    """Analyze spending trends by service."""
    logger.info("ff.node.analyze_trends")
    state = _to_dict(state)

    history = [SpendHistory(**h) for h in state.get("spend_history", [])]
    trends = await toolkit.analyze_trends(history)
    data = [t.model_dump() for t in trends]

    note = f"Analyzed {len(trends)} service trends"

    try:
        from .prompts import SYSTEM_TRENDS, TrendInsight

        ctx = json.dumps(
            {
                "trends": [
                    {
                        "service": t.service,
                        "provider": t.provider,
                        "direction": t.direction,
                        "growth_pct": t.growth_rate_pct,
                        "seasonality": t.seasonality,
                    }
                    for t in trends[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            TrendInsight,
            await llm_structured(
                system_prompt=SYSTEM_TRENDS,
                user_prompt=(f"Trend analysis:\n{ctx}"),
                schema=TrendInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ff",
            node="analyze_trends",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ff",
            node="analyze_trends",
        )

    return {
        "stage": FFStage.FORECAST_SPEND.value,
        "trend_analyses": data,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="analyze_trends",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ----------------------------------------------------------
# Node 3: Forecast Spend
# ----------------------------------------------------------


async def forecast_spend(
    state: dict[str, Any],
    toolkit: FinopsForecasterToolkit,
) -> dict[str, Any]:
    """Forecast future cloud spending."""
    logger.info("ff.node.forecast_spend")
    state = _to_dict(state)

    trends = [TrendAnalysis(**t) for t in state.get("trend_analyses", [])]
    forecasts = await toolkit.forecast_spend(trends)
    data = [f.model_dump() for f in forecasts]

    total = sum(f.projected_total for f in forecasts)
    overruns = sum(1 for f in forecasts if f.overrun_risk)
    note = f"Forecasted ${total:,.2f} total, {overruns} services at overrun risk"

    try:
        from .prompts import (
            SYSTEM_FORECAST,
            ForecastInsight,
        )

        ctx = json.dumps(
            {
                "forecasts": [
                    {
                        "service": f.service,
                        "projected": f.projected_total,
                        "overrun": f.overrun_risk,
                        "confidence": f.confidence_pct,
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
                user_prompt=(f"Spend forecast:\n{ctx}"),
                schema=ForecastInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ff",
            node="forecast_spend",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ff",
            node="forecast_spend",
        )

    return {
        "stage": FFStage.DETECT_ANOMALIES.value,
        "forecasts": data,
        "total_forecasted_spend": round(total, 2),
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="forecast_spend",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ----------------------------------------------------------
# Node 4: Detect Anomalies
# ----------------------------------------------------------


async def detect_anomalies(
    state: dict[str, Any],
    toolkit: FinopsForecasterToolkit,
) -> dict[str, Any]:
    """Detect cost anomalies in history."""
    logger.info("ff.node.detect_anomalies")
    state = _to_dict(state)

    history = [SpendHistory(**h) for h in state.get("spend_history", [])]
    forecasts = [SpendForecast(**f) for f in state.get("forecasts", [])]
    anomalies = await toolkit.detect_anomalies(
        history,
        forecasts,
    )
    data = [a.model_dump() for a in anomalies]

    critical = sum(1 for a in anomalies if a.severity == "critical")
    note = f"Detected {len(anomalies)} anomalies, {critical} critical"

    return {
        "stage": FFStage.RECOMMEND_COMMITMENTS.value,
        "anomalies": data,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_anomalies",
                detail=note,
                confidence=0.8,
            ).model_dump()
        ],
    }


# ----------------------------------------------------------
# Node 5: Recommend Commitments
# ----------------------------------------------------------


async def recommend_commitments(
    state: dict[str, Any],
    toolkit: FinopsForecasterToolkit,
) -> dict[str, Any]:
    """Recommend RI and savings plan purchases."""
    logger.info("ff.node.recommend_commitments")
    state = _to_dict(state)

    forecasts = [SpendForecast(**f) for f in state.get("forecasts", [])]
    trends = [TrendAnalysis(**t) for t in state.get("trend_analyses", [])]
    recs = await toolkit.recommend_commitments(
        forecasts,
        trends,
    )
    data = [r.model_dump() for r in recs]

    total_savings = sum(r.annual_savings for r in recs)
    note = f"Generated {len(recs)} commitment recs, ${total_savings:,.2f}/yr potential"

    return {
        "stage": FFStage.REPORT.value,
        "commitments": data,
        "total_potential_savings": round(
            total_savings,
            2,
        ),
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="recommend_commitments",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ----------------------------------------------------------
# Node 6: Report
# ----------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: FinopsForecasterToolkit,
) -> dict[str, Any]:
    """Compile the final forecast report."""
    logger.info("ff.node.report")
    state = _to_dict(state)

    total_forecast = state.get(
        "total_forecasted_spend",
        0.0,
    )
    total_savings = state.get(
        "total_potential_savings",
        0.0,
    )
    anomaly_count = len(
        state.get("anomalies", []),
    )
    rec_count = len(
        state.get("commitments", []),
    )
    overruns = sum(1 for f in state.get("forecasts", []) if f.get("overrun_risk"))

    lines = [
        "# FinOps Spending Forecast Report",
        "",
        f"**Forecasted spend:** ${total_forecast:,.2f}",
        f"**Commitment savings:** ${total_savings:,.2f}/yr",
        f"**Budget overrun risks:** {overruns}",
        f"**Cost anomalies:** {anomaly_count}",
        f"**Commitment recs:** {rec_count}",
    ]
    report_text = "\n".join(lines)

    try:
        from .prompts import (
            SYSTEM_REPORT,
            ReportInsight,
        )

        ctx = json.dumps(
            {
                "forecasted_spend": total_forecast,
                "potential_savings": total_savings,
                "anomalies": anomaly_count,
                "overrun_risks": overruns,
                "commitment_recs": rec_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Forecast report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ff",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ff",
            node="report",
        )

    return {
        "stage": FFStage.REPORT.value,
        "report": report_text,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final forecast report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
