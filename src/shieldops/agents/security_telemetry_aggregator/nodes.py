"""Node implementations for the Security Telemetry Aggregator."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_telemetry_aggregator.models import (
    ReasoningStep,
    SecurityTelemetryAggregatorState,
    STAStage,
)
from shieldops.agents.security_telemetry_aggregator.prompts import (
    SYSTEM_COLLECT,
    SYSTEM_CORRELATE,
    SYSTEM_ENRICH,
    SYSTEM_NORMALIZE,
    SYSTEM_ROUTE,
    AlertRoutingOutput,
    CorrelationOutput,
    EnrichmentOutput,
    NormalizationOutput,
    TelemetryCollectionOutput,
)
from shieldops.agents.security_telemetry_aggregator.tools import (
    SecurityTelemetryAggregatorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityTelemetryAggregatorToolkit | None = None


def set_toolkit(
    toolkit: SecurityTelemetryAggregatorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityTelemetryAggregatorToolkit:
    if _toolkit is None:
        return SecurityTelemetryAggregatorToolkit()
    return _toolkit


def _step(
    state: SecurityTelemetryAggregatorState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def collect_telemetry(
    state: SecurityTelemetryAggregatorState,
) -> dict[str, Any]:
    """Collect telemetry from all sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.collect_telemetry(state.config)

    try:
        ctx = _json.dumps(
            {
                "sources": state.config.get("sources", []),
                "count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COLLECT,
            user_prompt=f"Telemetry collection context:\n{ctx}",
            schema=TelemetryCollectionOutput,
        )
        if hasattr(llm_result, "total_collected"):
            logger.info("llm_enhanced", node="collect_telemetry")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_telemetry",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "collect_telemetry",
        f"sources={state.config.get('sources', [])}",
        f"collected {len(raw)} records",
        elapsed,
        "telemetry_bus",
    )
    await toolkit.record_metric(
        "records_collected",
        float(len(raw)),
    )

    return {
        "telemetry_records": raw,
        "stage": STAStage.NORMALIZE_SIGNALS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_telemetry",
        "session_start": start,
    }


async def normalize_signals(
    state: SecurityTelemetryAggregatorState,
) -> dict[str, Any]:
    """Normalize telemetry to common schema."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    normalized = await toolkit.normalize_signals(
        state.telemetry_records,
    )

    try:
        ctx = _json.dumps(
            {
                "record_count": len(state.telemetry_records),
                "normalized": len(normalized),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_NORMALIZE,
            user_prompt=f"Normalization context:\n{ctx}",
            schema=NormalizationOutput,
        )
        if hasattr(llm_result, "normalized_count"):
            logger.info(
                "llm_enhanced",
                node="normalize_signals",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="normalize_signals",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "normalize_signals",
        f"normalizing {len(state.telemetry_records)} records",
        f"{len(normalized)} normalized",
        elapsed,
        "normalizer",
    )

    return {
        "normalized_signals": normalized,
        "stage": STAStage.CORRELATE_EVENTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "normalize_signals",
    }


async def correlate_events(
    state: SecurityTelemetryAggregatorState,
) -> dict[str, Any]:
    """Correlate signals into event clusters."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    clusters = await toolkit.correlate_events(
        state.normalized_signals,
    )

    try:
        ctx = _json.dumps(
            {
                "signal_count": len(state.normalized_signals),
                "clusters": len(clusters),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CORRELATE,
            user_prompt=f"Correlation context:\n{ctx}",
            schema=CorrelationOutput,
        )
        if hasattr(llm_result, "clusters_found"):
            logger.info(
                "llm_enhanced",
                node="correlate_events",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="correlate_events",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "correlate_events",
        f"correlating {len(state.normalized_signals)} signals",
        f"{len(clusters)} clusters found",
        elapsed,
        "correlator",
    )
    await toolkit.record_metric(
        "clusters_found",
        float(len(clusters)),
    )

    return {
        "correlated_events": clusters,
        "stage": STAStage.ENRICH_CONTEXT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "correlate_events",
    }


async def enrich_context(
    state: SecurityTelemetryAggregatorState,
) -> dict[str, Any]:
    """Enrich correlated events with threat context."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    enriched = await toolkit.enrich_context(
        state.correlated_events,
    )

    try:
        ctx = _json.dumps(
            {
                "cluster_count": len(state.correlated_events),
                "enriched": len(enriched),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ENRICH,
            user_prompt=f"Enrichment context:\n{ctx}",
            schema=EnrichmentOutput,
        )
        if hasattr(llm_result, "enriched_count"):
            logger.info("llm_enhanced", node="enrich_context")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enrich_context",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "enrich_context",
        f"enriching {len(state.correlated_events)} clusters",
        f"{len(enriched)} enriched",
        elapsed,
        "enrichment_service",
    )

    return {
        "enriched_contexts": enriched,
        "stage": STAStage.ROUTE_ALERTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enrich_context",
    }


async def route_alerts(
    state: SecurityTelemetryAggregatorState,
) -> dict[str, Any]:
    """Route alerts to response teams."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    routings = await toolkit.route_alerts(
        state.enriched_contexts,
    )
    critical = sum(1 for r in routings if r.get("priority") == "critical")

    try:
        ctx = _json.dumps(
            {
                "enriched_count": len(state.enriched_contexts),
                "routed": len(routings),
                "critical": critical,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ROUTE,
            user_prompt=f"Alert routing context:\n{ctx}",
            schema=AlertRoutingOutput,
        )
        if hasattr(llm_result, "alerts_routed"):
            logger.info("llm_enhanced", node="route_alerts")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="route_alerts",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "route_alerts",
        f"routing {len(state.enriched_contexts)} enriched events",
        f"{len(routings)} routed, {critical} critical",
        elapsed,
        "alert_router",
    )
    await toolkit.record_metric(
        "alerts_routed",
        float(len(routings)),
    )

    return {
        "alert_routings": routings,
        "stage": STAStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "route_alerts",
    }


async def generate_report(
    state: SecurityTelemetryAggregatorState,
) -> dict[str, Any]:
    """Generate final aggregation report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "records_collected": len(state.telemetry_records),
        "signals_normalized": len(state.normalized_signals),
        "events_correlated": len(state.correlated_events),
        "contexts_enriched": len(state.enriched_contexts),
        "alerts_routed": len(state.alert_routings),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "generate_report",
        f"finalizing {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
