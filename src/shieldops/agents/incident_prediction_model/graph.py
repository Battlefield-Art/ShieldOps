"""LangGraph workflow for the Incident Prediction Model Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.incident_prediction_model.models import (
    IncidentPredictionModelState,
)
from shieldops.agents.incident_prediction_model.nodes import (
    analyze_patterns,
    assess_confidence,
    build_predictions,
    collect_signals,
    generate_report,
    recommend_preventions,
)
from shieldops.agents.tracing import traced_node

_AGENT = "incident_prediction_model"


def _should_predict(
    state: IncidentPredictionModelState,
) -> str:
    """Route after pattern analysis."""
    if state.error:
        return "generate_report"
    if state.patterns:
        return "build_predictions"
    return "generate_report"


def _should_prevent(
    state: IncidentPredictionModelState,
) -> str:
    """Route after confidence assessment."""
    if state.confidence_scores:
        return "recommend_preventions"
    return "generate_report"


def create_incident_prediction_model_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Incident Prediction Model LangGraph.

    Workflow:
        collect_signals -> analyze_patterns
          -> [has_patterns?] -> build_predictions -> assess_confidence
          -> [has_scores?] -> recommend_preventions -> generate_report
    """
    graph = StateGraph(IncidentPredictionModelState)

    graph.add_node(
        "collect_signals",
        traced_node(f"{_AGENT}.collect_signals", _AGENT)(collect_signals),
    )
    graph.add_node(
        "analyze_patterns",
        traced_node(f"{_AGENT}.analyze_patterns", _AGENT)(analyze_patterns),
    )
    graph.add_node(
        "build_predictions",
        traced_node(f"{_AGENT}.build_predictions", _AGENT)(build_predictions),
    )
    graph.add_node(
        "assess_confidence",
        traced_node(f"{_AGENT}.assess_confidence", _AGENT)(assess_confidence),
    )
    graph.add_node(
        "recommend_preventions",
        traced_node(f"{_AGENT}.recommend_preventions", _AGENT)(recommend_preventions),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("collect_signals")
    graph.add_edge("collect_signals", "analyze_patterns")
    graph.add_conditional_edges(
        "analyze_patterns",
        _should_predict,
        {
            "build_predictions": "build_predictions",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("build_predictions", "assess_confidence")
    graph.add_conditional_edges(
        "assess_confidence",
        _should_prevent,
        {
            "recommend_preventions": "recommend_preventions",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("recommend_preventions", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
