"""Anomaly Prediction Engine Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.anomaly_prediction_engine.models import (
    AnomalyPredictionEngineState,
)
from shieldops.agents.anomaly_prediction_engine.nodes import (
    generate_predictions,
    ingest_metrics,
    publish_alerts,
    report,
    train_models,
    validate_accuracy,
)
from shieldops.agents.tracing import traced_node

_AGENT = "anomaly_prediction_engine"


def _check_error(
    state: AnomalyPredictionEngineState,
) -> str:
    return "report" if state.error else "next"


def create_anomaly_prediction_engine_graph() -> StateGraph:
    """Build the Anomaly Prediction Engine workflow."""
    graph = StateGraph(AnomalyPredictionEngineState)

    graph.add_node(
        "ingest_metrics",
        traced_node("ape.ingest_metrics", _AGENT)(ingest_metrics),
    )
    graph.add_node(
        "train_models",
        traced_node("ape.train_models", _AGENT)(train_models),
    )
    graph.add_node(
        "generate_predictions",
        traced_node("ape.generate_predictions", _AGENT)(generate_predictions),
    )
    graph.add_node(
        "validate_accuracy",
        traced_node("ape.validate_accuracy", _AGENT)(validate_accuracy),
    )
    graph.add_node(
        "publish_alerts",
        traced_node("ape.publish_alerts", _AGENT)(publish_alerts),
    )
    graph.add_node(
        "report",
        traced_node("ape.report", _AGENT)(report),
    )

    graph.set_entry_point("ingest_metrics")

    graph.add_conditional_edges(
        "ingest_metrics",
        _check_error,
        {"report": "report", "next": "train_models"},
    )
    graph.add_conditional_edges(
        "train_models",
        _check_error,
        {"report": "report", "next": "generate_predictions"},
    )
    graph.add_conditional_edges(
        "generate_predictions",
        _check_error,
        {"report": "report", "next": "validate_accuracy"},
    )
    graph.add_conditional_edges(
        "validate_accuracy",
        _check_error,
        {"report": "report", "next": "publish_alerts"},
    )
    graph.add_edge("publish_alerts", "report")
    graph.add_edge("report", END)

    return graph
