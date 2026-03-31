"""Event Stream Processor Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    ESPStage,
    ParsedEvent,
    ReasoningStep,
    StreamConnection,
)
from .tools import EventStreamProcessorToolkit

logger = structlog.get_logger()

_toolkit: EventStreamProcessorToolkit | None = None


def set_toolkit(toolkit: EventStreamProcessorToolkit) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> EventStreamProcessorToolkit:
    if _toolkit is None:
        return EventStreamProcessorToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Connect Streams
# ------------------------------------------------------------------


async def connect_streams(
    state: dict[str, Any],
    toolkit: EventStreamProcessorToolkit,
) -> dict[str, Any]:
    """Connect to Kafka topics and establish stream consumers."""
    logger.info("esp.node.connect_streams")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    connections = await toolkit.connect_streams(tenant_id)
    data = [c.model_dump() for c in connections]

    note = f"Connected {len(connections)} Kafka streams for tenant {tenant_id}"

    return {
        "stage": ESPStage.PARSE_EVENTS.value,
        "stream_connections": data,
        "current_step": "connect_streams",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="connect_streams",
                detail=note,
                confidence=0.95,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Parse Events
# ------------------------------------------------------------------


async def parse_events(
    state: dict[str, Any],
    toolkit: EventStreamProcessorToolkit,
) -> dict[str, Any]:
    """Parse CEF/LEEF/JSON/OCSF events from connected streams."""
    logger.info("esp.node.parse_events")
    state = _to_dict(state)

    connections = [StreamConnection(**c) for c in state.get("stream_connections", [])]
    events = await toolkit.parse_events(connections)
    data = [e.model_dump() for e in events]

    note = f"Parsed {len(events)} events from {len(connections)} streams"

    return {
        "stage": ESPStage.ENRICH.value,
        "parsed_events": data,
        "total_events_processed": len(events),
        "current_step": "parse_events",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="parse_events",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Enrich
# ------------------------------------------------------------------


async def enrich(
    state: dict[str, Any],
    toolkit: EventStreamProcessorToolkit,
) -> dict[str, Any]:
    """Enrich parsed events with threat intel, geo, and ASN context."""
    logger.info("esp.node.enrich")
    state = _to_dict(state)

    events = [ParsedEvent(**e) for e in state.get("parsed_events", [])]
    enriched_list = await toolkit.enrich_events(events)
    data = [e.model_dump() for e in enriched_list]

    ioc_matches = sum(1 for e in enriched_list if e.threat_intel_match)
    note = f"Enriched {len(enriched_list)} events; {ioc_matches} IOC matches"

    try:
        from .prompts import SYSTEM_ENRICH, EnrichmentInsight

        ctx = json.dumps(
            {
                "events": [
                    {
                        "source_ip": ev.source_ip,
                        "event_type": ev.event_type,
                        "severity": ev.severity,
                    }
                    for ev in events[:20]
                ],
                "enriched_sample": [
                    {
                        "hostname": en.hostname,
                        "risk_score": en.risk_score,
                        "ioc_match": en.threat_intel_match,
                        "tags": en.tags,
                    }
                    for en in enriched_list[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            EnrichmentInsight,
            await llm_structured(
                system_prompt=SYSTEM_ENRICH,
                user_prompt=f"Enrichment context:\n{ctx}",
                schema=EnrichmentInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="esp",
            node="enrich",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="esp",
            node="enrich",
        )

    return {
        "stage": ESPStage.CORRELATE.value,
        "enriched_events": data,
        "current_step": "enrich",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="enrich",
                detail=note,
                confidence=0.87,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Correlate
# ------------------------------------------------------------------


async def correlate(
    state: dict[str, Any],
    toolkit: EventStreamProcessorToolkit,
) -> dict[str, Any]:
    """Apply correlation rules across enriched event stream."""
    logger.info("esp.node.correlate")
    state = _to_dict(state)

    from .models import EnrichedEvent

    events = [ParsedEvent(**e) for e in state.get("parsed_events", [])]
    enriched = [EnrichedEvent(**e) for e in state.get("enriched_events", [])]
    correlations = await toolkit.correlate_events(events, enriched)
    data = [c.model_dump() for c in correlations]

    critical_count = sum(1 for c in correlations if c.severity.value in ("critical", "high"))
    note = f"Fired {len(correlations)} rules; {critical_count} critical/high severity"

    try:
        from .prompts import SYSTEM_CORRELATE, CorrelationInsight

        ctx = json.dumps(
            {
                "rules_fired": [
                    {
                        "rule_name": c.rule_name,
                        "severity": c.severity,
                        "confidence": c.confidence,
                        "mitre": c.mitre_technique,
                    }
                    for c in correlations
                ],
            },
            default=str,
        )
        llm_result = cast(
            CorrelationInsight,
            await llm_structured(
                system_prompt=SYSTEM_CORRELATE,
                user_prompt=f"Correlation results:\n{ctx}",
                schema=CorrelationInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="esp",
            node="correlate",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="esp",
            node="correlate",
        )

    return {
        "stage": ESPStage.ROUTE.value,
        "correlations": data,
        "correlations_fired": len(correlations),
        "current_step": "correlate",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="correlate",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Route
# ------------------------------------------------------------------


async def route(
    state: dict[str, Any],
    toolkit: EventStreamProcessorToolkit,
) -> dict[str, Any]:
    """Route correlated alerts to SIEM, SOAR, or ticketing destinations."""
    logger.info("esp.node.route")
    state = _to_dict(state)

    from .models import CorrelationRule

    correlations = [CorrelationRule(**c) for c in state.get("correlations", [])]
    decisions = await toolkit.route_events(correlations)
    data = [d.model_dump() for d in decisions]

    soar_triggered = sum(1 for d in decisions if d.soar_triggered)
    note = f"Created {len(decisions)} routing decisions; {soar_triggered} SOAR triggers"

    try:
        from .prompts import SYSTEM_REPORT, RoutingInsight

        ctx = json.dumps(
            {
                "decisions": [
                    {
                        "destination": d.destination,
                        "priority": d.priority,
                        "soar": d.soar_triggered,
                        "ticket": d.ticket_created,
                    }
                    for d in decisions
                ],
            },
            default=str,
        )
        llm_result = cast(
            RoutingInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Routing decisions:\n{ctx}",
                schema=RoutingInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="esp",
            node="route",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="esp",
            node="route",
        )

    return {
        "stage": ESPStage.REPORT.value,
        "route_decisions": data,
        "current_step": "route",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="route",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: EventStreamProcessorToolkit,
) -> dict[str, Any]:
    """Compile the final event stream processing report."""
    logger.info("esp.node.report")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    total_events = state.get("total_events_processed", 0)
    correlations_fired = state.get("correlations_fired", 0)
    routes = len(state.get("route_decisions", []))
    streams = len(state.get("stream_connections", []))

    await toolkit.record_metric(
        tenant_id=tenant_id,
        events_processed=total_events,
        correlations_fired=correlations_fired,
        routes_created=routes,
    )

    lines = [
        "# Event Stream Processor Report",
        "",
        f"**Streams connected:** {streams}",
        f"**Events processed:** {total_events}",
        f"**Correlation rules fired:** {correlations_fired}",
        f"**Routing decisions created:** {routes}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "streams": streams,
                "total_events": total_events,
                "correlations": correlations_fired,
                "routes": routes,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Stream processor session:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="esp",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="esp",
            node="report",
        )

    return {
        "stage": ESPStage.REPORT.value,
        "report": report_text,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final stream processing report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
