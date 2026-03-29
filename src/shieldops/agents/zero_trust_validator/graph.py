"""Zero Trust Validator Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node
from shieldops.agents.zero_trust_validator.models import ZeroTrustValidatorState
from shieldops.agents.zero_trust_validator.nodes import (
    assess_posture,
    check_identity,
    inspect_traffic,
    inventory_assets,
    report,
    verify_access,
)

_AGENT = "zero_trust_validator"


def _check_error(state: ZeroTrustValidatorState) -> str:
    return "report" if state.error else "next"


def create_zero_trust_validator_graph() -> StateGraph:
    """Build the Zero Trust Validator workflow."""
    graph = StateGraph(ZeroTrustValidatorState)

    graph.add_node(
        "inventory_assets",
        traced_node(f"{_AGENT}.inventory_assets", _AGENT)(inventory_assets),
    )
    graph.add_node(
        "check_identity",
        traced_node(f"{_AGENT}.check_identity", _AGENT)(check_identity),
    )
    graph.add_node(
        "verify_access",
        traced_node(f"{_AGENT}.verify_access", _AGENT)(verify_access),
    )
    graph.add_node(
        "inspect_traffic",
        traced_node(f"{_AGENT}.inspect_traffic", _AGENT)(inspect_traffic),
    )
    graph.add_node(
        "assess_posture",
        traced_node(f"{_AGENT}.assess_posture", _AGENT)(assess_posture),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("inventory_assets")

    graph.add_conditional_edges(
        "inventory_assets",
        _check_error,
        {"next": "check_identity", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_identity",
        _check_error,
        {"next": "verify_access", "report": "report"},
    )
    graph.add_conditional_edges(
        "verify_access",
        _check_error,
        {"next": "inspect_traffic", "report": "report"},
    )
    graph.add_conditional_edges(
        "inspect_traffic",
        _check_error,
        {"next": "assess_posture", "report": "report"},
    )
    graph.add_edge("assess_posture", "report")
    graph.add_edge("report", END)

    return graph
