"""Threat Correlation Engine Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.threat_correlation_engine.models import ThreatCorrelationEngineState
from shieldops.agents.threat_correlation_engine.nodes import (
    collect_events,
    correlate_signals,
    generate_alerts,
    normalize_data,
    report,
    score_threats,
)
from shieldops.agents.tracing import traced_node

_AGENT = "threat_correlation_engine"


def _check_error(state: ThreatCorrelationEngineState) -> str:
    return "report" if state.error else "next"


def create_threat_correlation_engine_graph() -> StateGraph:
    """Build the Threat Correlation Engine workflow."""
    graph = StateGraph(ThreatCorrelationEngineState)

    graph.add_node(
        "collect_events",
        traced_node(f"{_AGENT}.collect_events", _AGENT)(collect_events),
    )
    graph.add_node(
        "normalize_data",
        traced_node(f"{_AGENT}.normalize_data", _AGENT)(normalize_data),
    )
    graph.add_node(
        "correlate_signals",
        traced_node(f"{_AGENT}.correlate_signals", _AGENT)(correlate_signals),
    )
    graph.add_node(
        "score_threats",
        traced_node(f"{_AGENT}.score_threats", _AGENT)(score_threats),
    )
    graph.add_node(
        "generate_alerts",
        traced_node(f"{_AGENT}.generate_alerts", _AGENT)(generate_alerts),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_events")

    graph.add_conditional_edges(
        "collect_events",
        _check_error,
        {"next": "normalize_data", "report": "report"},
    )
    graph.add_conditional_edges(
        "normalize_data",
        _check_error,
        {"next": "correlate_signals", "report": "report"},
    )
    graph.add_conditional_edges(
        "correlate_signals",
        _check_error,
        {"next": "score_threats", "report": "report"},
    )
    graph.add_conditional_edges(
        "score_threats",
        _check_error,
        {"next": "generate_alerts", "report": "report"},
    )
    graph.add_edge("generate_alerts", "report")
    graph.add_edge("report", END)

    return graph
