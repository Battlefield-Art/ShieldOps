"""LangGraph workflow definition for the Security Event
Enricher Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_event_enricher.models import (
    SecurityEventEnricherState,
)
from shieldops.agents.security_event_enricher.nodes import (
    enrich_threat,
    generate_report,
    lookup_context,
    receive_events,
    route_events,
    score_priority,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_event_enricher"


def _should_route(
    state: SecurityEventEnricherState,
) -> str:
    """Route after scoring: route if events scored or on
    error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.scored_events:
        return "route_events"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Event Enricher LangGraph
    workflow.

    Workflow:
        receive_events -> lookup_context
            -> enrich_threat -> score_priority
            -> [scored? -> route_events]
            -> generate_report -> END
    """
    graph = StateGraph(SecurityEventEnricherState)

    graph.add_node(
        "receive_events",
        traced_node(f"{_AGENT}.receive_events", _AGENT)(receive_events),
    )
    graph.add_node(
        "lookup_context",
        traced_node(f"{_AGENT}.lookup_context", _AGENT)(lookup_context),
    )
    graph.add_node(
        "enrich_threat",
        traced_node(f"{_AGENT}.enrich_threat", _AGENT)(enrich_threat),
    )
    graph.add_node(
        "score_priority",
        traced_node(f"{_AGENT}.score_priority", _AGENT)(score_priority),
    )
    graph.add_node(
        "route_events",
        traced_node(f"{_AGENT}.route_events", _AGENT)(route_events),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("receive_events")
    graph.add_edge("receive_events", "lookup_context")
    graph.add_edge("lookup_context", "enrich_threat")
    graph.add_edge("enrich_threat", "score_priority")
    graph.add_conditional_edges(
        "score_priority",
        _should_route,
        {
            "route_events": "route_events",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("route_events", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_event_enricher_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Event Enricher
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
