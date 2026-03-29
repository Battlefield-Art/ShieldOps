"""Incident Prediction Engine Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.incident_prediction_engine.models import IncidentPredictionEngineState
from shieldops.agents.incident_prediction_engine.nodes import (
    alert,
    collect_signals,
    extract_features,
    rank_predictions,
    report,
    run_models,
)
from shieldops.agents.tracing import traced_node

_AGENT = "incident_prediction_engine"


def _check_error(state: IncidentPredictionEngineState) -> str:
    return "report" if state.error else "next"


def create_incident_prediction_engine_graph() -> StateGraph:
    """Build the Incident Prediction Engine workflow."""
    graph = StateGraph(IncidentPredictionEngineState)

    graph.add_node(
        "collect_signals",
        traced_node(f"{_AGENT}.collect_signals", _AGENT)(collect_signals),
    )
    graph.add_node(
        "extract_features",
        traced_node(f"{_AGENT}.extract_features", _AGENT)(extract_features),
    )
    graph.add_node(
        "run_models",
        traced_node(f"{_AGENT}.run_models", _AGENT)(run_models),
    )
    graph.add_node(
        "rank_predictions",
        traced_node(f"{_AGENT}.rank_predictions", _AGENT)(rank_predictions),
    )
    graph.add_node(
        "alert",
        traced_node(f"{_AGENT}.alert", _AGENT)(alert),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_signals")

    graph.add_conditional_edges(
        "collect_signals",
        _check_error,
        {"next": "extract_features", "report": "report"},
    )
    graph.add_conditional_edges(
        "extract_features",
        _check_error,
        {"next": "run_models", "report": "report"},
    )
    graph.add_conditional_edges(
        "run_models",
        _check_error,
        {"next": "rank_predictions", "report": "report"},
    )
    graph.add_conditional_edges(
        "rank_predictions",
        _check_error,
        {"next": "alert", "report": "report"},
    )
    graph.add_edge("alert", "report")
    graph.add_edge("report", END)

    return graph
