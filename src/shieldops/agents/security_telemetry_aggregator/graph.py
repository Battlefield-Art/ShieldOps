"""LangGraph workflow for the Security Telemetry Aggregator."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_telemetry_aggregator.models import (
    SecurityTelemetryAggregatorState,
)
from shieldops.agents.security_telemetry_aggregator.nodes import (
    collect_telemetry,
    correlate_events,
    enrich_context,
    generate_report,
    normalize_signals,
    route_alerts,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_telemetry_aggregator"


def _should_correlate(
    state: SecurityTelemetryAggregatorState,
) -> str:
    if state.error:
        return "generate_report"
    if state.normalized_signals:
        return "correlate_events"
    return "generate_report"


def _should_enrich(
    state: SecurityTelemetryAggregatorState,
) -> str:
    if state.correlated_events:
        return "enrich_context"
    return "generate_report"


def create_security_telemetry_aggregator_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Telemetry Aggregator LangGraph.

    Workflow:
        collect_telemetry -> normalize_signals
          -> [has_signals?] -> correlate_events
          -> [has_clusters?] -> enrich_context -> route_alerts
          -> generate_report
    """
    graph = StateGraph(SecurityTelemetryAggregatorState)

    graph.add_node(
        "collect_telemetry",
        traced_node(f"{_AGENT}.collect_telemetry", _AGENT)(
            collect_telemetry,
        ),
    )
    graph.add_node(
        "normalize_signals",
        traced_node(f"{_AGENT}.normalize_signals", _AGENT)(
            normalize_signals,
        ),
    )
    graph.add_node(
        "correlate_events",
        traced_node(f"{_AGENT}.correlate_events", _AGENT)(
            correlate_events,
        ),
    )
    graph.add_node(
        "enrich_context",
        traced_node(f"{_AGENT}.enrich_context", _AGENT)(
            enrich_context,
        ),
    )
    graph.add_node(
        "route_alerts",
        traced_node(f"{_AGENT}.route_alerts", _AGENT)(
            route_alerts,
        ),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(
            generate_report,
        ),
    )

    graph.set_entry_point("collect_telemetry")
    graph.add_edge("collect_telemetry", "normalize_signals")
    graph.add_conditional_edges(
        "normalize_signals",
        _should_correlate,
        {
            "correlate_events": "correlate_events",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "correlate_events",
        _should_enrich,
        {
            "enrich_context": "enrich_context",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("enrich_context", "route_alerts")
    graph.add_edge("route_alerts", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
