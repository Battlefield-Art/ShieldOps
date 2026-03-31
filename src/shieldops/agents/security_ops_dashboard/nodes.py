"""Security Ops Dashboard Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    DashboardInsight,
    KPIResult,
    MetricAnomaly,
    ReasoningStep,
    SecurityMetric,
    SODStage,
)
from .tools import SecurityOpsDashboardToolkit

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
    toolkit: SecurityOpsDashboardToolkit,
) -> dict[str, Any]:
    """Collect security operations metrics."""
    logger.info("sod.node.collect_metrics")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    metrics = await toolkit.collect_metrics(tenant_id)
    data = [m.model_dump() for m in metrics]

    note = f"Collected {len(metrics)} security metrics"

    return {
        "stage": SODStage.CALCULATE_KPIS.value,
        "metrics": data,
        "total_metrics_collected": len(metrics),
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
# Node 2: Calculate KPIs
# ------------------------------------------------------------------


async def calculate_kpis(
    state: dict[str, Any],
    toolkit: SecurityOpsDashboardToolkit,
) -> dict[str, Any]:
    """Calculate KPIs from raw metrics."""
    logger.info("sod.node.calculate_kpis")
    state = _to_dict(state)

    metrics = [SecurityMetric(**m) for m in state.get("metrics", [])]
    kpis = await toolkit.calculate_kpis(metrics)
    data = [k.model_dump() for k in kpis]

    meeting_target = sum(1 for k in kpis if k.meets_target)
    note = f"Calculated {len(kpis)} KPIs, {meeting_target} meeting target"

    try:
        from .prompts import SYSTEM_KPI, KPIInsight

        ctx = json.dumps(
            {
                "kpis": [
                    {
                        "name": k.kpi_name,
                        "value": k.value,
                        "target": k.target,
                        "meets": k.meets_target,
                        "delta": k.delta_pct,
                    }
                    for k in kpis
                ],
            },
            default=str,
        )
        llm_result = cast(
            KPIInsight,
            await llm_structured(
                system_prompt=SYSTEM_KPI,
                user_prompt=f"Security KPIs:\n{ctx}",
                schema=KPIInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sod",
            node="calculate_kpis",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sod",
            node="calculate_kpis",
        )

    return {
        "stage": SODStage.DETECT_ANOMALIES.value,
        "kpi_results": data,
        "kpis_calculated": len(kpis),
        "current_step": "calculate_kpis",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="calculate_kpis",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Detect Anomalies
# ------------------------------------------------------------------


async def detect_anomalies(
    state: dict[str, Any],
    toolkit: SecurityOpsDashboardToolkit,
) -> dict[str, Any]:
    """Detect anomalies in metric data."""
    logger.info("sod.node.detect_anomalies")
    state = _to_dict(state)

    metrics = [SecurityMetric(**m) for m in state.get("metrics", [])]
    anomalies = await toolkit.detect_metric_anomalies(metrics)
    data = [a.model_dump() for a in anomalies]

    high_sev = sum(1 for a in anomalies if a.severity == "high")
    note = f"Detected {len(anomalies)} anomalies, {high_sev} high severity"

    return {
        "stage": SODStage.GENERATE_INSIGHTS.value,
        "anomalies": data,
        "current_step": "detect_anomalies",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_anomalies",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Generate Insights
# ------------------------------------------------------------------


async def generate_insights(
    state: dict[str, Any],
    toolkit: SecurityOpsDashboardToolkit,
) -> dict[str, Any]:
    """Generate actionable insights from KPIs and anomalies."""
    logger.info("sod.node.generate_insights")
    state = _to_dict(state)

    kpis = [KPIResult(**k) for k in state.get("kpi_results", [])]
    anomalies = [MetricAnomaly(**a) for a in state.get("anomalies", [])]
    insights = await toolkit.generate_insights(kpis, anomalies)
    data = [ins.model_dump() for ins in insights]

    high_priority = sum(1 for ins in insights if ins.priority == "high")
    note = f"Generated {len(insights)} insights, {high_priority} high priority"

    return {
        "stage": SODStage.BUILD_VIEWS.value,
        "insights": data,
        "current_step": "generate_insights",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="generate_insights",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Build Views
# ------------------------------------------------------------------


async def build_views(
    state: dict[str, Any],
    toolkit: SecurityOpsDashboardToolkit,
) -> dict[str, Any]:
    """Build configured dashboard views."""
    logger.info("sod.node.build_views")
    state = _to_dict(state)

    kpis = [KPIResult(**k) for k in state.get("kpi_results", [])]
    insights = [DashboardInsight(**ins) for ins in state.get("insights", [])]
    views = await toolkit.build_dashboard_views(kpis, insights)
    data = [v.model_dump() for v in views]

    note = f"Built {len(views)} dashboard views"

    return {
        "stage": SODStage.REPORT.value,
        "dashboard_views": data,
        "current_step": "build_views",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="build_views",
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
    toolkit: SecurityOpsDashboardToolkit,
) -> dict[str, Any]:
    """Compile the final security ops dashboard report."""
    logger.info("sod.node.report")
    state = _to_dict(state)

    total_metrics = state.get("total_metrics_collected", 0)
    kpi_count = state.get("kpis_calculated", 0)
    anomaly_count = len(state.get("anomalies", []))
    insight_count = len(state.get("insights", []))
    view_count = len(state.get("dashboard_views", []))

    lines = [
        "# Security Ops Dashboard Report",
        "",
        f"**Metrics collected:** {total_metrics}",
        f"**KPIs calculated:** {kpi_count}",
        f"**Anomalies detected:** {anomaly_count}",
        f"**Insights generated:** {insight_count}",
        f"**Views built:** {view_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "metrics": total_metrics,
                "kpis": kpi_count,
                "anomalies": anomaly_count,
                "insights": insight_count,
                "views": view_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Security ops dashboard report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sod",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sod",
            node="report",
        )

    return {
        "stage": SODStage.REPORT.value,
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
