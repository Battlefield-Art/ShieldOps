"""Credential Rotation Manager Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.credential_rotation_manager.models import CredentialRotationManagerState
from shieldops.agents.credential_rotation_manager.nodes import (
    check_age,
    discover_credentials,
    execute_rotation,
    report,
    schedule_rotation,
    validate,
)
from shieldops.agents.tracing import traced_node

_AGENT = "credential_rotation_manager"


def _check_error(state: CredentialRotationManagerState) -> str:
    return "report" if state.error else "next"


def create_credential_rotation_manager_graph() -> StateGraph:
    """Build the Credential Rotation Manager workflow."""
    graph = StateGraph(CredentialRotationManagerState)

    graph.add_node(
        "discover_credentials",
        traced_node(f"{_AGENT}.discover_credentials", _AGENT)(discover_credentials),
    )
    graph.add_node(
        "check_age",
        traced_node(f"{_AGENT}.check_age", _AGENT)(check_age),
    )
    graph.add_node(
        "schedule_rotation",
        traced_node(f"{_AGENT}.schedule_rotation", _AGENT)(schedule_rotation),
    )
    graph.add_node(
        "execute_rotation",
        traced_node(f"{_AGENT}.execute_rotation", _AGENT)(execute_rotation),
    )
    graph.add_node(
        "validate",
        traced_node(f"{_AGENT}.validate", _AGENT)(validate),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_credentials")

    graph.add_conditional_edges(
        "discover_credentials",
        _check_error,
        {"next": "check_age", "report": "report"},
    )
    graph.add_conditional_edges(
        "check_age",
        _check_error,
        {"next": "schedule_rotation", "report": "report"},
    )
    graph.add_conditional_edges(
        "schedule_rotation",
        _check_error,
        {"next": "execute_rotation", "report": "report"},
    )
    graph.add_conditional_edges(
        "execute_rotation",
        _check_error,
        {"next": "validate", "report": "report"},
    )
    graph.add_edge("validate", "report")
    graph.add_edge("report", END)

    return graph
