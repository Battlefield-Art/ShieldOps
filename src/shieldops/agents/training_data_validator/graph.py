"""Training Data Validator Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node
from shieldops.agents.training_data_validator.models import TrainingDataValidatorState
from shieldops.agents.training_data_validator.nodes import (
    analyze_bias,
    check_labels,
    detect_poisoning,
    profile_data,
    report,
    validate_provenance,
)

_AGENT = "training_data_validator"


def _check_error(state: TrainingDataValidatorState) -> str:
    return "report" if state.error else "next"


def create_training_data_validator_graph() -> StateGraph:
    """Build the Training Data Validator LangGraph workflow."""
    graph = StateGraph(TrainingDataValidatorState)

    graph.add_node(
        "profile_data",
        traced_node(f"{_AGENT}.profile_data", _AGENT)(profile_data),
    )
    graph.add_node(
        "check_labels",
        traced_node(f"{_AGENT}.check_labels", _AGENT)(check_labels),
    )
    graph.add_node(
        "detect_poisoning",
        traced_node(f"{_AGENT}.detect_poisoning", _AGENT)(detect_poisoning),
    )
    graph.add_node(
        "analyze_bias",
        traced_node(f"{_AGENT}.analyze_bias", _AGENT)(analyze_bias),
    )
    graph.add_node(
        "validate_provenance",
        traced_node(f"{_AGENT}.validate_provenance", _AGENT)(validate_provenance),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("profile_data")

    graph.add_conditional_edges(
        "profile_data",
        _check_error,
        {"next": "check_labels", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_labels",
        _check_error,
        {"next": "detect_poisoning", "report": "report"},
    )
    graph.add_conditional_edges(
        "detect_poisoning",
        _check_error,
        {"next": "analyze_bias", "report": "report"},
    )
    graph.add_conditional_edges(
        "analyze_bias",
        _check_error,
        {"next": "validate_provenance", "report": "report"},
    )
    graph.add_edge("validate_provenance", "report")
    graph.add_edge("report", END)

    return graph
