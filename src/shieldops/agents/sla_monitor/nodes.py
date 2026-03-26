"""Node implementations for the SLA Monitor Agent LangGraph workflow."""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.sla_monitor.models import (
    BurnRateAlert,
    ReasoningStep,
    SLAMonitorState,
    SLIMetric,
    SLOStatus,
)
from shieldops.agents.sla_monitor.prompts import SYSTEM_BURN_RATE, BurnRateAnalysisOutput
from shieldops.agents.sla_monitor.tools import SLAMonitorToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SLAMonitorToolkit | None = None


def set_toolkit(toolkit: SLAMonitorToolkit) -> None:
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> SLAMonitorToolkit:
    if _toolkit is None:
        return SLAMonitorToolkit()
    return _toolkit


async def collect_slis(state: SLAMonitorState) -> dict[str, Any]:
    """Collect SLI metrics for all monitored services."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_metrics = await toolkit.collect_sli_metrics(state.tenant_id, state.services)
    sli_metrics = [SLIMetric(**m) for m in raw_metrics if isinstance(m, dict)]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_slis",
        input_summary=f"Collecting SLIs for {len(state.services)} services",
        output_summary=f"Collected {len(sli_metrics)} SLI metrics",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="metrics_provider",
    )

    await toolkit.record_metric("sli_collection_count", float(len(sli_metrics)))

    return {
        "sli_metrics": sli_metrics,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_slis",
        "session_start": start,
    }


async def calculate_slos(state: SLAMonitorState) -> dict[str, Any]:
    """Calculate SLO compliance from collected SLI metrics."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sli_dicts = [m.model_dump() for m in state.sli_metrics]
    raw_statuses = await toolkit.calculate_slo_status(sli_dicts)
    slo_statuses = [SLOStatus(**s) for s in raw_statuses if isinstance(s, dict)]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="calculate_slos",
        input_summary=f"Calculating SLOs from {len(state.sli_metrics)} SLIs",
        output_summary=f"Computed {len(slo_statuses)} SLO statuses",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="slo_store",
    )

    return {
        "slo_statuses": slo_statuses,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "calculate_slos",
    }


async def track_error_budgets(state: SLAMonitorState) -> dict[str, Any]:
    """Track error budget consumption across all SLOs."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    slo_dicts = [s.model_dump() for s in state.slo_statuses]
    budget_summary = await toolkit.track_error_budgets(slo_dicts)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="track_error_budgets",
        input_summary=f"Tracking budgets for {len(state.slo_statuses)} SLOs",
        output_summary=(
            f"Budget health: {budget_summary.get('health_pct', 0)}%, "
            f"exhausted: {budget_summary.get('exhausted', 0)}"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="slo_store",
    )

    return {
        "budget_summary": budget_summary,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "track_error_budgets",
    }


async def detect_burn_rates(state: SLAMonitorState) -> dict[str, Any]:
    """Detect abnormal error budget burn rates."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    slo_dicts = [s.model_dump() for s in state.slo_statuses]
    raw_alerts = await toolkit.detect_burn_rates(slo_dicts)
    burn_rate_alerts = [BurnRateAlert(**a) for a in raw_alerts if isinstance(a, dict)]

    # LLM enhancement: deeper burn rate analysis
    if burn_rate_alerts:
        try:
            import json as _json

            context = _json.dumps(
                {
                    "tenant_id": state.tenant_id,
                    "slo_statuses": slo_dicts[:20],
                    "burn_rate_alerts": [a.model_dump() for a in burn_rate_alerts[:10]],
                    "budget_summary": state.budget_summary,
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_BURN_RATE,
                user_prompt=f"Burn rate analysis context:\n{context}",
                schema=BurnRateAnalysisOutput,
            )
            if hasattr(llm_result, "recommended_actions"):
                for i, alert in enumerate(burn_rate_alerts):
                    if i < len(llm_result.recommended_actions):
                        alert.recommended_action = llm_result.recommended_actions[i]
            logger.info(
                "llm_enhanced",
                node="detect_burn_rates",
                severity=getattr(llm_result, "severity", "unknown"),
            )
        except Exception:
            logger.debug("llm_enhancement_skipped", node="detect_burn_rates")

    has_alerts = len(burn_rate_alerts) > 0

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_burn_rates",
        input_summary=f"Analyzing burn rates for {len(state.slo_statuses)} SLOs",
        output_summary=f"Detected {len(burn_rate_alerts)} burn rate alerts",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="alerting_engine",
    )

    await toolkit.record_metric("burn_rate_alert_count", float(len(burn_rate_alerts)))

    return {
        "burn_rate_alerts": burn_rate_alerts,
        "has_alerts": has_alerts,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_burn_rates",
    }


async def alert(state: SLAMonitorState) -> dict[str, Any]:
    """Send alerts for detected burn rate violations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    alerts_sent: list[dict[str, Any]] = []
    for burn_alert in state.burn_rate_alerts:
        result = await toolkit.send_alert(burn_alert.model_dump())
        alerts_sent.append(result)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="alert",
        input_summary=f"Sending {len(state.burn_rate_alerts)} burn rate alerts",
        output_summary=f"Sent {len(alerts_sent)} alerts",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="notification_service",
    )

    return {
        "alerts_sent": alerts_sent,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "alert",
    }


async def report(state: SLAMonitorState) -> dict[str, Any]:
    """Generate final SLA monitoring report."""
    start = datetime.now(UTC)

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    # Build report summary
    slo_breakdown: dict[str, int] = {}
    for slo in state.slo_statuses:
        status = (
            slo.budget_status.value
            if hasattr(slo.budget_status, "value")
            else str(slo.budget_status)
        )
        slo_breakdown[status] = slo_breakdown.get(status, 0) + 1

    services_at_risk = [
        slo.service for slo in state.slo_statuses if slo.budget_remaining_pct < 25.0
    ]

    report_data: dict[str, Any] = {
        "tenant_id": state.tenant_id,
        "services_monitored": len(state.services),
        "sli_metrics_collected": len(state.sli_metrics),
        "slo_statuses": len(state.slo_statuses),
        "slo_breakdown": slo_breakdown,
        "budget_summary": state.budget_summary,
        "burn_rate_alerts": len(state.burn_rate_alerts),
        "alerts_sent": len(state.alerts_sent),
        "services_at_risk": services_at_risk,
        "duration_ms": duration_ms,
    }

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary=f"Generating report for {len(state.services)} services",
        output_summary=f"Report complete; {len(services_at_risk)} services at risk",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "report": report_data,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
