"""Node implementations for the Security Event Enricher
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_event_enricher.models import (
    ReasoningStep,
    SecurityEventEnricherState,
    SEEStage,
)
from shieldops.agents.security_event_enricher.prompts import (
    SYSTEM_CONTEXT,
    SYSTEM_PRIORITY,
    SYSTEM_REPORT,
    SYSTEM_THREAT_ENRICHMENT,
    ContextLookupOutput,
    EnrichmentReportOutput,
    PriorityScoringOutput,
    ThreatEnrichmentOutput,
)
from shieldops.agents.security_event_enricher.tools import (
    SecurityEventEnricherToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityEventEnricherToolkit | None = None


def set_toolkit(
    toolkit: SecurityEventEnricherToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityEventEnricherToolkit:
    if _toolkit is None:
        return SecurityEventEnricherToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: datetime,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: receive_events
# ------------------------------------------------------------------


async def receive_events(
    state: SecurityEventEnricherState,
) -> dict[str, Any]:
    """Receive a batch of security events from configured
    sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sources = [s.value for s in state.event_sources]
    results = await toolkit.receive_events(
        sources=sources,
        batch_size=state.batch_size,
    )

    events: list[dict[str, Any]] = list(results)

    step = _step(
        state.reasoning_chain,
        "receive_events",
        f"Sources: {len(sources)}, batch={state.batch_size}",
        f"Received {len(events)} events",
        start,
        "siem_client",
    )

    return {
        "events": events,
        "total_events": len(events),
        "stage": SEEStage.RECEIVE_EVENTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "receive_events",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: lookup_context
# ------------------------------------------------------------------


async def lookup_context(
    state: SecurityEventEnricherState,
) -> dict[str, Any]:
    """Look up asset, user, and geo context for events."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    context = await toolkit.lookup_context(
        events=state.events,
    )

    context_list: list[dict[str, Any]] = list(context)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "event_count": len(state.events),
                "sample": state.events[:3],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_CONTEXT,
            user_prompt=f"Enrich with context:\n{ctx}",
            schema=ContextLookupOutput,
        )
        _rand = random.randint(1000, 9999)  # noqa: S311
        context_list.append(
            {
                "context_id": f"llm-{_rand}",
                "criticality": llm_out.asset_criticality,  # type: ignore[union-attr]
                "user_risk": llm_out.user_risk,  # type: ignore[union-attr]
                "geo_anomaly": llm_out.geo_anomaly,  # type: ignore[union-attr]
                "summary": llm_out.summary,  # type: ignore[union-attr]
            }
        )
        logger.info(
            "llm_enhanced",
            node="lookup_context",
            geo_anomaly=llm_out.geo_anomaly,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="lookup_context",
        )

    step = _step(
        state.reasoning_chain,
        "lookup_context",
        f"Looking up context for {len(state.events)} events",
        f"Produced {len(context_list)} context records",
        start,
        "asset_inventory",
    )

    return {
        "context_lookups": context_list,
        "stage": SEEStage.LOOKUP_CONTEXT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "lookup_context",
    }


# ------------------------------------------------------------------
# Node: enrich_threat
# ------------------------------------------------------------------


async def enrich_threat(
    state: SecurityEventEnricherState,
) -> dict[str, Any]:
    """Enrich events with threat intelligence data."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    enrichments = await toolkit.enrich_with_threat_intel(
        events=state.events,
        context=state.context_lookups,
    )

    enrichment_list: list[dict[str, Any]] = list(enrichments)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "events_sample": state.events[:3],
                "context_sample": state.context_lookups[:3],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_THREAT_ENRICHMENT,
            user_prompt=f"Enrich with threat intel:\n{ctx}",
            schema=ThreatEnrichmentOutput,
        )
        if llm_out.ioc_matches:  # type: ignore[union-attr]
            _rand2 = random.randint(1000, 9999)  # noqa: S311
            enrichment_list.append(
                {
                    "enrichment_id": f"llm-{_rand2}",
                    "ioc_matches": llm_out.ioc_matches,  # type: ignore[union-attr]
                    "mitre": llm_out.mitre_techniques,  # type: ignore[union-attr]
                    "threat_actor": llm_out.threat_actor,  # type: ignore[union-attr]
                    "confidence": llm_out.confidence,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="enrich_threat",
            iocs=len(llm_out.ioc_matches),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enrich_threat",
        )

    step = _step(
        state.reasoning_chain,
        "enrich_threat",
        f"Enriching {len(state.events)} events with threat intel",
        f"Produced {len(enrichment_list)} enrichments",
        start,
        "threat_intel",
    )

    return {
        "enrichments": enrichment_list,
        "enriched_count": len(enrichment_list),
        "stage": SEEStage.ENRICH_THREAT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enrich_threat",
    }


# ------------------------------------------------------------------
# Node: score_priority
# ------------------------------------------------------------------


async def score_priority(
    state: SecurityEventEnricherState,
) -> dict[str, Any]:
    """Score enriched events by priority for triage."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scored = await toolkit.score_priority(
        enriched=state.enrichments,
    )

    scored_list: list[dict[str, Any]] = list(scored)
    critical = sum(1 for s in scored_list if s.get("priority") == "critical")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "enrichments_sample": state.enrichments[:5],
                "event_count": state.total_events,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_PRIORITY,
            user_prompt=f"Score event priority:\n{ctx}",
            schema=PriorityScoringOutput,
        )
        if llm_out.factors:  # type: ignore[union-attr]
            scored_list.append(
                {
                    "priority": llm_out.priority,  # type: ignore[union-attr]
                    "score": llm_out.score,  # type: ignore[union-attr]
                    "factors": llm_out.factors,  # type: ignore[union-attr]
                    "auto_actionable": llm_out.auto_actionable,  # type: ignore[union-attr]
                }
            )
            if llm_out.priority == "critical":  # type: ignore[union-attr]
                critical += 1
        logger.info(
            "llm_enhanced",
            node="score_priority",
            priority=llm_out.priority,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="score_priority",
        )

    step = _step(
        state.reasoning_chain,
        "score_priority",
        f"Scoring {len(state.enrichments)} enriched events",
        f"Scored {len(scored_list)} events, {critical} critical",
        start,
        "priority_scorer",
    )

    return {
        "scored_events": scored_list,
        "critical_count": critical,
        "stage": SEEStage.SCORE_PRIORITY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "score_priority",
    }


# ------------------------------------------------------------------
# Node: route_events
# ------------------------------------------------------------------


async def route_events(
    state: SecurityEventEnricherState,
) -> dict[str, Any]:
    """Route scored events to appropriate teams."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    routing = await toolkit.route_events(
        scored=state.scored_events,
    )

    step = _step(
        state.reasoning_chain,
        "route_events",
        f"Routing {len(state.scored_events)} scored events",
        f"Routed {len(routing)} events",
        start,
        "routing_engine",
    )

    return {
        "routing_decisions": routing,
        "routed_count": len(routing),
        "stage": SEEStage.ROUTE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "route_events",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecurityEventEnricherState,
) -> dict[str, Any]:
    """Generate the enrichment pipeline report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "total_events": state.total_events,
        "enriched_count": state.enriched_count,
        "critical_count": state.critical_count,
        "routed_count": state.routed_count,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "total_events": state.total_events,
                "enriched": state.enriched_count,
                "critical": state.critical_count,
                "routed": state.routed_count,
                "scored_sample": state.scored_events[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate enrichment report:\n{ctx}",
            schema=EnrichmentReportOutput,
        )
        if isinstance(llm_out, EnrichmentReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "pipeline_health": llm_out.pipeline_health,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recs=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    await toolkit.record_metric(
        request_id=state.request_id,
        outcome={
            "total_events": state.total_events,
            "enriched": state.enriched_count,
            "critical": state.critical_count,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_events} events",
        f"Report generated, {state.critical_count} critical",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": SEEStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
