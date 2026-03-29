"""Tokenization Manager Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.tokenization_manager.models import TokenizationManagerState
from shieldops.agents.tokenization_manager.nodes import (
    discover_fields,
    generate_tokens,
    map_vault,
    report,
    rotate,
    validate_integrity,
)
from shieldops.agents.tracing import traced_node

_AGENT = "tokenization_manager"


def _check_error(state: TokenizationManagerState) -> str:
    return "report" if state.error else "next"


def create_tokenization_manager_graph() -> StateGraph:
    """Build the Tokenization Manager workflow."""
    graph = StateGraph(TokenizationManagerState)

    graph.add_node(
        "discover_fields",
        traced_node(f"{_AGENT}.discover_fields", _AGENT)(discover_fields),
    )
    graph.add_node(
        "generate_tokens",
        traced_node(f"{_AGENT}.generate_tokens", _AGENT)(generate_tokens),
    )
    graph.add_node(
        "map_vault",
        traced_node(f"{_AGENT}.map_vault", _AGENT)(map_vault),
    )
    graph.add_node(
        "validate_integrity",
        traced_node(f"{_AGENT}.validate_integrity", _AGENT)(validate_integrity),
    )
    graph.add_node(
        "rotate",
        traced_node(f"{_AGENT}.rotate", _AGENT)(rotate),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("discover_fields")

    graph.add_conditional_edges(
        "discover_fields",
        _check_error,
        {"next": "generate_tokens", "report": "report"},
    )
    graph.add_conditional_edges(
        "generate_tokens",
        _check_error,
        {"next": "map_vault", "report": "report"},
    )
    graph.add_conditional_edges(
        "map_vault",
        _check_error,
        {"next": "validate_integrity", "report": "report"},
    )
    graph.add_conditional_edges(
        "validate_integrity",
        _check_error,
        {"next": "rotate", "report": "report"},
    )
    graph.add_edge("rotate", "report")
    graph.add_edge("report", END)

    return graph
