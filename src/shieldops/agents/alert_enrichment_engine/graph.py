"""Alert Enrichment Engine Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.alert_enrichment_engine.models import AlertEnrichmentEngineState
from shieldops.agents.alert_enrichment_engine.nodes import (
    correlate_intel,
    ingest_alert,
    lookup_context,
    report,
    route,
    score_priority,
)
from shieldops.agents.tracing import traced_node

_AGENT = "alert_enrichment_engine"


def _check_error(state: AlertEnrichmentEngineState) -> str:
    return "report" if state.error else "next"


def create_alert_enrichment_engine_graph() -> StateGraph:
    """Build the Alert Enrichment Engine workflow."""
    graph = StateGraph(AlertEnrichmentEngineState)

    graph.add_node(
        "ingest_alert",
        traced_node(f"{_AGENT}.ingest_alert", _AGENT)(ingest_alert),
    )
    graph.add_node(
        "lookup_context",
        traced_node(f"{_AGENT}.lookup_context", _AGENT)(lookup_context),
    )
    graph.add_node(
        "correlate_intel",
        traced_node(f"{_AGENT}.correlate_intel", _AGENT)(correlate_intel),
    )
    graph.add_node(
        "score_priority",
        traced_node(f"{_AGENT}.score_priority", _AGENT)(score_priority),
    )
    graph.add_node(
        "route",
        traced_node(f"{_AGENT}.route", _AGENT)(route),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("ingest_alert")

    graph.add_conditional_edges(
        "ingest_alert",
        _check_error,
        {"next": "lookup_context", "report": "report"},
    )
    graph.add_conditional_edges(
        "lookup_context",
        _check_error,
        {"next": "correlate_intel", "report": "report"},
    )
    graph.add_conditional_edges(
        "correlate_intel",
        _check_error,
        {"next": "score_priority", "report": "report"},
    )
    graph.add_conditional_edges(
        "score_priority",
        _check_error,
        {"next": "route", "report": "report"},
    )
    graph.add_edge("route", "report")
    graph.add_edge("report", END)

    return graph
