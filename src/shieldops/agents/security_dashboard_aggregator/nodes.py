"""Node implementations for the Dashboard Aggregator Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_dashboard_aggregator.models import (
    AggregatorStage,
    SecurityDashboardAggregatorState,
)
from shieldops.agents.security_dashboard_aggregator.prompts import (
    SYSTEM_ANOMALY,
    SYSTEM_KPI,
    SYSTEM_REPORT,
    AnomalyDetectionOutput,
    DashboardReportOutput,
    KPIAnalysisOutput,
)
from shieldops.agents.security_dashboard_aggregator.tools import (
    SecurityDashboardAggregatorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityDashboardAggregatorToolkit | None = None


def _get_toolkit() -> SecurityDashboardAggregatorToolkit:
    if _toolkit is None:
        return SecurityDashboardAggregatorToolkit()
    return _toolkit


async def collect_agent_metrics(
    state: SecurityDashboardAggregatorState,
) -> dict[str, Any]:
    """Collect metrics from all agents."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    metrics = await toolkit.collect_agent_metrics(
        tenant_id=state.tenant_id,
    )
    agents = {m.agent_name for m in metrics}

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "agent_metrics": metrics,
        "agents_reporting": len(agents),
        "current_stage": (AggregatorStage.COLLECT_AGENT_METRICS),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Collected {len(metrics)} metrics from {len(agents)} agents ({elapsed}ms)",
        ],
    }


async def aggregate_by_domain(
    state: SecurityDashboardAggregatorState,
) -> dict[str, Any]:
    """Aggregate metrics by domain."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    aggregates = await toolkit.aggregate_by_domain(
        state.agent_metrics,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "domain_aggregates": aggregates,
        "current_stage": (AggregatorStage.AGGREGATE_BY_DOMAIN),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Aggregated into {len(aggregates)} domains ({elapsed}ms)",
        ],
    }


async def calculate_kpis(
    state: SecurityDashboardAggregatorState,
) -> dict[str, Any]:
    """Calculate KPIs from aggregated data."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    kpis = await toolkit.calculate_kpis(
        state.domain_aggregates,
        state.agent_metrics,
    )

    # LLM enrichment for KPI analysis
    for kpi in kpis:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_KPI,
                user_prompt=(
                    f"KPI: {kpi.name}\n"
                    f"Value: {kpi.value}\n"
                    f"Target: {kpi.target}\n"
                    f"Status: {kpi.status}"
                ),
                output_schema=KPIAnalysisOutput,
            )
            kpi.trend_pct = result.trend_pct
        except Exception:
            logger.warning(
                "dashboard_agg.kpi_fallback",
                kpi_name=kpi.name,
            )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "kpis": kpis,
        "current_stage": (AggregatorStage.CALCULATE_KPIS),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Calculated {len(kpis)} KPIs ({elapsed}ms)",
        ],
    }


async def detect_anomalies(
    state: SecurityDashboardAggregatorState,
) -> dict[str, Any]:
    """Detect anomalies in agent metrics."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    anomalies = await toolkit.detect_anomalies(
        state.agent_metrics,
    )

    # LLM enrichment for anomaly context
    for anomaly in anomalies:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_ANOMALY,
                user_prompt=(
                    f"Agent: {anomaly.agent_name}\n"
                    f"Metric: {anomaly.metric_name}\n"
                    f"Expected: "
                    f"{anomaly.expected_value}\n"
                    f"Actual: {anomaly.actual_value}\n"
                    f"Deviation: "
                    f"{anomaly.deviation_pct}%"
                ),
                output_schema=(AnomalyDetectionOutput),
            )
            anomaly.severity = result.severity
            anomaly.description = result.description
        except Exception:
            logger.warning(
                "dashboard_agg.anomaly_fallback",
                agent=anomaly.agent_name,
            )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    freshness = elapsed / 1000.0
    return {
        "anomalies": anomalies,
        "data_freshness_seconds": freshness,
        "current_stage": (AggregatorStage.DETECT_ANOMALIES),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Detected {len(anomalies)} anomalies ({elapsed}ms)",
        ],
    }


async def generate_dashboard(
    state: SecurityDashboardAggregatorState,
) -> dict[str, Any]:
    """Generate the CISO dashboard."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    dashboard = await toolkit.generate_dashboard(
        state.domain_aggregates,
        state.kpis,
        state.anomalies,
        state.agents_reporting,
    )

    # LLM enrichment for executive summary
    try:
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(
                f"Score: {dashboard.overall_score}\n"
                f"Risk: {dashboard.risk_level}\n"
                f"Agents: {dashboard.agents_healthy}"
                f"/{dashboard.agents_total}\n"
                f"Anomalies: {len(state.anomalies)}\n"
                f"KPIs: {len(state.kpis)}"
            ),
            output_schema=DashboardReportOutput,
        )
        dashboard.executive_summary = result.executive_summary
        dashboard.overall_score = result.overall_score
        dashboard.risk_level = result.risk_level
    except Exception:
        logger.warning("dashboard_agg.dashboard_llm_fallback")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "dashboard_data": dashboard,
        "current_stage": (AggregatorStage.GENERATE_DASHBOARD),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Dashboard generated: score {dashboard.overall_score} ({elapsed}ms)",
        ],
    }


async def generate_report(
    state: SecurityDashboardAggregatorState,
) -> dict[str, Any]:
    """Generate the final aggregator report."""
    start = datetime.now(UTC)

    summary = (
        f"Security score: "
        f"{state.dashboard_data.overall_score}/100, "
        f"risk: {state.dashboard_data.risk_level}, "
        f"{state.agents_reporting} agents reporting"
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "current_stage": AggregatorStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report: {summary[:100]} ({elapsed}ms)",
        ],
        "session_duration_ms": (state.session_duration_ms + elapsed),
    }
