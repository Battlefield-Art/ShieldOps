"""Node implementations for the Alert Correlation Agent LangGraph workflow."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.alert_correlation.models import (
    AlertCorrelationState,
    AlertPriority,
    CorrelationStage,
    PrioritizedIncident,
    ReasoningStep,
)
from shieldops.agents.alert_correlation.prompts import (
    SYSTEM_CORRELATE,
    SYSTEM_PRIORITIZE,
    SYSTEM_REPORT,
    CorrelationAnalysisOutput,
    CorrelationReportOutput,
    IncidentPrioritizationOutput,
)
from shieldops.agents.alert_correlation.tools import AlertCorrelationToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AlertCorrelationToolkit | None = None


def set_toolkit(toolkit: AlertCorrelationToolkit) -> None:
    """Set the global toolkit instance for nodes."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> AlertCorrelationToolkit:
    if _toolkit is None:
        return AlertCorrelationToolkit()
    return _toolkit


async def collect_alerts(state: AlertCorrelationState) -> dict[str, Any]:
    """Collect raw alerts from all configured sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_alerts = await toolkit.collect_raw_alerts(
        tenant_id=state.tenant_id,
        time_window_minutes=state.time_window_minutes,
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_alerts",
        input_summary=(f"tenant={state.tenant_id}, window={state.time_window_minutes}m"),
        output_summary=f"Collected {len(raw_alerts)} raw alerts",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="collect_raw_alerts",
    )

    return {
        "raw_alerts": raw_alerts,
        "total_alerts_ingested": len(raw_alerts),
        "current_stage": CorrelationStage.COLLECT_ALERTS,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def normalize_alerts(state: AlertCorrelationState) -> dict[str, Any]:
    """Normalize collected alerts to a common schema."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    normalized = await toolkit.normalize_alerts(state.raw_alerts)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="normalize_alerts",
        input_summary=f"{len(state.raw_alerts)} raw alerts",
        output_summary=f"Normalized {len(normalized)} alerts",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="normalize_alerts",
    )

    return {
        "normalized_alerts": normalized,
        "current_stage": CorrelationStage.NORMALIZE,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def correlate_alerts(state: AlertCorrelationState) -> dict[str, Any]:
    """Correlate normalized alerts into clusters using multiple strategies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    clusters = await toolkit.correlate_alerts(state.normalized_alerts)

    # LLM enrichment: generate root cause hypotheses for clusters
    for cluster in clusters:
        cluster_alert_summaries = []
        for alert in state.normalized_alerts:
            if alert.id in cluster.alert_ids:
                cluster_alert_summaries.append(f"[{alert.severity}] {alert.source}: {alert.title}")

        try:
            result = await llm_structured(
                system_prompt=SYSTEM_CORRELATE,
                user_prompt=(
                    "Alerts in cluster:\n"
                    + "\n".join(cluster_alert_summaries)
                    + f"\n\nCorrelation type: {cluster.correlation_type}"
                    + f"\nAffected assets: {', '.join(cluster.affected_assets)}"
                ),
                output_schema=CorrelationAnalysisOutput,
            )
            cluster.root_cause_hypothesis = result.root_cause_hypothesis
            cluster.confidence = max(cluster.confidence, result.confidence)
            if result.kill_chain_stage:
                cluster.kill_chain_stage = result.kill_chain_stage
        except Exception:
            logger.warning(
                "alert_correlation.llm_correlate_fallback",
                cluster_id=cluster.id,
            )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="correlate_alerts",
        input_summary=f"{len(state.normalized_alerts)} normalized alerts",
        output_summary=f"Formed {len(clusters)} correlation clusters",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="correlate_alerts",
    )

    return {
        "clusters": clusters,
        "current_stage": CorrelationStage.CORRELATE,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def build_kill_chains(
    state: AlertCorrelationState,
) -> dict[str, Any]:
    """Enrich clusters with kill chain stage mapping."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    enriched_clusters = await toolkit.build_kill_chains(
        clusters=state.clusters,
        alerts=state.normalized_alerts,
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="build_kill_chains",
        input_summary=f"{len(state.clusters)} clusters",
        output_summary=(f"Enriched {len(enriched_clusters)} clusters with kill chain stages"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="build_kill_chains",
    )

    return {
        "clusters": enriched_clusters,
        "current_stage": CorrelationStage.BUILD_CHAINS,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def prioritize_incidents(
    state: AlertCorrelationState,
) -> dict[str, Any]:
    """Prioritize correlation clusters into actionable incidents."""
    start = datetime.now(UTC)

    incidents: list[PrioritizedIncident] = []
    for cluster in state.clusters:
        # Build context for LLM prioritization
        cluster_alerts = [a for a in state.normalized_alerts if a.id in cluster.alert_ids]
        alert_summary = "\n".join(f"- [{a.severity}] {a.source}: {a.title}" for a in cluster_alerts)

        try:
            result = await llm_structured(
                system_prompt=SYSTEM_PRIORITIZE,
                user_prompt=(
                    f"Cluster ID: {cluster.id}\n"
                    f"Correlation type: {cluster.correlation_type}\n"
                    f"Kill chain stage: {cluster.kill_chain_stage}\n"
                    f"Confidence: {cluster.confidence:.2f}\n"
                    f"Root cause: {cluster.root_cause_hypothesis}\n"
                    f"Affected assets: {', '.join(cluster.affected_assets)}\n"
                    f"\nConstituent alerts:\n{alert_summary}"
                ),
                output_schema=IncidentPrioritizationOutput,
            )
            incidents.append(
                PrioritizedIncident(
                    id=f"inc-{uuid4().hex[:8]}",
                    cluster_id=cluster.id,
                    priority=AlertPriority(result.priority),
                    title=result.title,
                    narrative=result.narrative,
                    recommended_action=result.recommended_action,
                    auto_actionable=result.auto_actionable,
                    estimated_impact=result.estimated_impact,
                )
            )
        except Exception:
            logger.warning(
                "alert_correlation.llm_prioritize_fallback",
                cluster_id=cluster.id,
            )
            # Fallback: derive priority from severity of constituent alerts
            severities = [a.severity for a in cluster_alerts]
            if "critical" in severities:
                priority = AlertPriority.P1
            elif "high" in severities:
                priority = AlertPriority.P2
            elif "medium" in severities:
                priority = AlertPriority.P3
            else:
                priority = AlertPriority.P4
            incidents.append(
                PrioritizedIncident(
                    id=f"inc-{uuid4().hex[:8]}",
                    cluster_id=cluster.id,
                    priority=priority,
                    title=(
                        cluster.root_cause_hypothesis
                        or f"Correlated incident from {len(cluster.alert_ids)} alerts"
                    ),
                    narrative=f"Kill chain stage: {cluster.kill_chain_stage}",
                    recommended_action="Investigate correlated alerts",
                    auto_actionable=False,
                    estimated_impact="Unknown",
                )
            )

    # Sort by priority
    priority_order = {
        AlertPriority.P1: 1,
        AlertPriority.P2: 2,
        AlertPriority.P3: 3,
        AlertPriority.P4: 4,
        AlertPriority.P5: 5,
    }
    incidents.sort(key=lambda i: priority_order.get(i.priority, 5))

    # Calculate noise reduction ratio
    total_alerts = state.total_alerts_ingested
    noise_ratio = 0.0
    if total_alerts > 0 and len(incidents) > 0:
        noise_ratio = total_alerts / len(incidents)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="prioritize_incidents",
        input_summary=f"{len(state.clusters)} clusters",
        output_summary=(f"Created {len(incidents)} incidents, noise reduction {noise_ratio:.1f}:1"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm_structured",
    )

    return {
        "incidents": incidents,
        "total_incidents_created": len(incidents),
        "noise_reduction_ratio": noise_ratio,
        "current_stage": CorrelationStage.PRIORITIZE,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def generate_report(
    state: AlertCorrelationState,
) -> dict[str, Any]:
    """Generate the final correlation report with executive summary."""
    start = datetime.now(UTC)

    try:
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(
                f"Total raw alerts: {state.total_alerts_ingested}\n"
                f"Correlation clusters: {len(state.clusters)}\n"
                f"Prioritized incidents: {len(state.incidents)}\n"
                f"Noise reduction ratio: {state.noise_reduction_ratio:.1f}:1\n"
                f"\nIncidents:\n"
                + "\n".join(f"- [{i.priority}] {i.title}" for i in state.incidents)
            ),
            output_schema=CorrelationReportOutput,
        )
        report_summary = result.executive_summary
    except Exception:
        logger.warning("alert_correlation.llm_report_fallback")
        report_summary = (
            f"Correlated {state.total_alerts_ingested} alerts into "
            f"{len(state.incidents)} incidents "
            f"({state.noise_reduction_ratio:.1f}:1 noise reduction)."
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=(
            f"{len(state.incidents)} incidents, {state.noise_reduction_ratio:.1f}:1 ratio"
        ),
        output_summary=report_summary[:120],
        duration_ms=elapsed,
        tool_used="llm_structured",
    )

    return {
        "current_stage": CorrelationStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "session_duration_ms": sum(s.duration_ms for s in state.reasoning_chain) + elapsed,
    }
