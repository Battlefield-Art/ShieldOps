"""Federated Learning Security Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.federated_learning_security.models import FederatedLearningSecurityState
from shieldops.agents.federated_learning_security.nodes import (
    assess_risk,
    detect_poisoning,
    inspect_gradients,
    report,
    score_participants,
    verify_aggregation,
)
from shieldops.agents.tracing import traced_node

_AGENT = "federated_learning_security"


def _check_error(state: FederatedLearningSecurityState) -> str:
    return "report" if state.error else "next"


def create_federated_learning_security_graph() -> StateGraph:
    """Build the Federated Learning Security LangGraph workflow."""
    graph = StateGraph(FederatedLearningSecurityState)

    graph.add_node(
        "inspect_gradients",
        traced_node(f"{_AGENT}.inspect_gradients", _AGENT)(inspect_gradients),
    )
    graph.add_node(
        "detect_poisoning",
        traced_node(f"{_AGENT}.detect_poisoning", _AGENT)(detect_poisoning),
    )
    graph.add_node(
        "score_participants",
        traced_node(f"{_AGENT}.score_participants", _AGENT)(score_participants),
    )
    graph.add_node(
        "verify_aggregation",
        traced_node(f"{_AGENT}.verify_aggregation", _AGENT)(verify_aggregation),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("inspect_gradients")

    graph.add_conditional_edges(
        "inspect_gradients",
        _check_error,
        {"next": "detect_poisoning", "report": "report"},
    )
    graph.add_conditional_edges(
        "detect_poisoning",
        _check_error,
        {"next": "score_participants", "report": "report"},
    )
    graph.add_conditional_edges(
        "score_participants",
        _check_error,
        {"next": "verify_aggregation", "report": "report"},
    )
    graph.add_conditional_edges(
        "verify_aggregation",
        _check_error,
        {"next": "assess_risk", "report": "report"},
    )
    graph.add_edge("assess_risk", "report")
    graph.add_edge("report", END)

    return graph
