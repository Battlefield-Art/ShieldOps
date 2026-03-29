"""model_drift_detector graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.model_drift_detector.models import ModelDriftDetectorState
from shieldops.agents.model_drift_detector.nodes import (
    analyze_concept_drift,
    analyze_data_drift,
    analyze_prediction_drift,
    collect,
    complete,
    evaluate_thresholds,
    failed,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "model_drift_detector"


def _check_error(state: ModelDriftDetectorState) -> str:
    return "report" if state.error else "next"


def create_model_drift_detector_graph() -> StateGraph:
    graph = StateGraph(ModelDriftDetectorState)

    graph.add_node(
        "collect",
        traced_node(f"{_AGENT}.collect", _AGENT)(collect),
    )
    graph.add_node(
        "analyze_data_drift",
        traced_node(f"{_AGENT}.analyze_data_drift", _AGENT)(analyze_data_drift),
    )
    graph.add_node(
        "analyze_concept_drift",
        traced_node(f"{_AGENT}.analyze_concept_drift", _AGENT)(analyze_concept_drift),
    )
    graph.add_node(
        "analyze_prediction_drift",
        traced_node(f"{_AGENT}.analyze_prediction_drift", _AGENT)(analyze_prediction_drift),
    )
    graph.add_node(
        "evaluate_thresholds",
        traced_node(f"{_AGENT}.evaluate_thresholds", _AGENT)(evaluate_thresholds),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )
    graph.add_node(
        "complete",
        traced_node(f"{_AGENT}.complete", _AGENT)(complete),
    )
    graph.add_node(
        "failed",
        traced_node(f"{_AGENT}.failed", _AGENT)(failed),
    )

    graph.set_entry_point("collect")

    graph.add_conditional_edges(
        "collect",
        _check_error,
        {"next": "analyze_data_drift", "report": "report"},
    )
    graph.add_conditional_edges(
        "analyze_data_drift",
        _check_error,
        {"next": "analyze_concept_drift", "report": "report"},
    )
    graph.add_conditional_edges(
        "analyze_concept_drift",
        _check_error,
        {"next": "analyze_prediction_drift", "report": "report"},
    )
    graph.add_conditional_edges(
        "analyze_prediction_drift",
        _check_error,
        {"next": "evaluate_thresholds", "report": "report"},
    )
    graph.add_edge("evaluate_thresholds", "report")
    graph.add_conditional_edges(
        "report",
        _check_error,
        {"next": "complete", "report": "report"},
    )
    graph.add_conditional_edges(
        "complete",
        _check_error,
        {"next": "failed", "report": "report"},
    )
    graph.add_edge("report", END)

    return graph
