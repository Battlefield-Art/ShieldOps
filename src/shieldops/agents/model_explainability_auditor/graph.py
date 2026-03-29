"""Model Explainability Auditor Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.model_explainability_auditor.models import ModelExplainabilityAuditorState
from shieldops.agents.model_explainability_auditor.nodes import (
    analyze_shap,
    check_fairness,
    collect_predictions,
    compute_importance,
    generate_report,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "model_explainability_auditor"


def _check_error(state: ModelExplainabilityAuditorState) -> str:
    return "report" if state.error else "next"


def create_model_explainability_auditor_graph() -> StateGraph:
    """Build the Model Explainability Auditor LangGraph workflow."""
    graph = StateGraph(ModelExplainabilityAuditorState)

    graph.add_node(
        "collect_predictions",
        traced_node(f"{_AGENT}.collect_predictions", _AGENT)(collect_predictions),
    )
    graph.add_node(
        "compute_importance",
        traced_node(f"{_AGENT}.compute_importance", _AGENT)(compute_importance),
    )
    graph.add_node(
        "analyze_shap",
        traced_node(f"{_AGENT}.analyze_shap", _AGENT)(analyze_shap),
    )
    graph.add_node(
        "check_fairness",
        traced_node(f"{_AGENT}.check_fairness", _AGENT)(check_fairness),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_predictions")

    graph.add_conditional_edges(
        "collect_predictions",
        _check_error,
        {"next": "compute_importance", "report": "report"},
    )
    graph.add_conditional_edges(
        "compute_importance",
        _check_error,
        {"next": "analyze_shap", "report": "report"},
    )
    graph.add_conditional_edges(
        "analyze_shap",
        _check_error,
        {"next": "check_fairness", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_fairness",
        _check_error,
        {"next": "generate_report", "report": "report"},
    )
    graph.add_edge("generate_report", "report")
    graph.add_edge("report", END)

    return graph
