"""Serverless Security Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ServerlessSecurityState
from .nodes import (
    analyze_permissions,
    assess_risk,
    detect_threats,
    discover_functions,
    scan_dependencies,
)
from .tools import ServerlessSecurityToolkit


def _has_error(state: Any) -> str:
    """Route to END if an error occurred."""
    err = state.get("error", "") if isinstance(state, dict) else getattr(state, "error", "")
    return "end" if err else "continue"


def build_graph(
    toolkit: ServerlessSecurityToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Serverless Security agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_functions(_to_dict(state), toolkit)

    async def _permissions(state: Any) -> dict[str, Any]:
        return await analyze_permissions(_to_dict(state), toolkit)

    async def _deps(state: Any) -> dict[str, Any]:
        return await scan_dependencies(_to_dict(state), toolkit)

    async def _threats(state: Any) -> dict[str, Any]:
        return await detect_threats(_to_dict(state), toolkit)

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_risk(_to_dict(state), toolkit)

    graph = StateGraph(ServerlessSecurityState)

    graph.add_node("discover_functions", _discover)
    graph.add_node("analyze_permissions", _permissions)
    graph.add_node("scan_dependencies", _deps)
    graph.add_node("detect_threats", _threats)
    graph.add_node("assess_risk", _assess)

    graph.set_entry_point("discover_functions")
    graph.add_conditional_edges(
        "discover_functions",
        _has_error,
        {"end": END, "continue": "analyze_permissions"},
    )
    graph.add_edge("analyze_permissions", "scan_dependencies")
    graph.add_edge("scan_dependencies", "detect_threats")
    graph.add_edge("detect_threats", "assess_risk")
    graph.add_edge("assess_risk", END)

    return graph


def create_serverless_security_graph(
    cloud_clients: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Serverless Security agent graph."""
    toolkit = ServerlessSecurityToolkit(
        cloud_clients=cloud_clients,
    )
    return build_graph(toolkit)
