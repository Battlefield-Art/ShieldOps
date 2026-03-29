"""Consent Manager Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.consent_manager.models import ConsentManagerState
from shieldops.agents.consent_manager.nodes import (
    audit,
    check_expiry,
    collect_consents,
    enforce_preferences,
    report,
    validate_purposes,
)
from shieldops.agents.tracing import traced_node

_AGENT = "consent_manager"


def _check_error(state: ConsentManagerState) -> str:
    return "report" if state.error else "next"


def create_consent_manager_graph() -> StateGraph:
    """Build the Consent Manager workflow."""
    graph = StateGraph(ConsentManagerState)

    graph.add_node(
        "collect_consents",
        traced_node(f"{_AGENT}.collect_consents", _AGENT)(collect_consents),
    )
    graph.add_node(
        "validate_purposes",
        traced_node(f"{_AGENT}.validate_purposes", _AGENT)(validate_purposes),
    )
    graph.add_node(
        "check_expiry",
        traced_node(f"{_AGENT}.check_expiry", _AGENT)(check_expiry),
    )
    graph.add_node(
        "enforce_preferences",
        traced_node(f"{_AGENT}.enforce_preferences", _AGENT)(enforce_preferences),
    )
    graph.add_node(
        "audit",
        traced_node(f"{_AGENT}.audit", _AGENT)(audit),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_consents")

    graph.add_conditional_edges(
        "collect_consents",
        _check_error,
        {"next": "validate_purposes", "report": "report"},
    )
    graph.add_conditional_edges(
        "validate_purposes",
        _check_error,
        {"next": "check_expiry", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_expiry",
        _check_error,
        {"next": "enforce_preferences", "report": "report"},
    )
    graph.add_conditional_edges(
        "enforce_preferences",
        _check_error,
        {"next": "audit", "report": "report"},
    )
    graph.add_edge("audit", "report")
    graph.add_edge("report", END)

    return graph
