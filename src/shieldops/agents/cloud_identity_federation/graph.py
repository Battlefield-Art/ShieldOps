"""Cloud Identity Federation Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CloudIdentityFederationState
from .nodes import (
    analyze_trust,
    assess_risk,
    detect_misconfigs,
    discover_identities,
    map_federations,
)
from .tools import CloudIdentityFederationToolkit


def _has_error(state: Any) -> str:
    """Route to END if an error occurred."""
    err = state.get("error", "") if isinstance(state, dict) else getattr(state, "error", "")
    return "end" if err else "continue"


def build_graph(
    toolkit: CloudIdentityFederationToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Identity Federation agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_identities(_to_dict(state), toolkit)

    async def _map(state: Any) -> dict[str, Any]:
        return await map_federations(_to_dict(state), toolkit)

    async def _misconfigs(state: Any) -> dict[str, Any]:
        return await detect_misconfigs(_to_dict(state), toolkit)

    async def _trust(state: Any) -> dict[str, Any]:
        return await analyze_trust(_to_dict(state), toolkit)

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_risk(_to_dict(state), toolkit)

    graph = StateGraph(CloudIdentityFederationState)

    graph.add_node("discover_identities", _discover)
    graph.add_node("map_federations", _map)
    graph.add_node("detect_misconfigs", _misconfigs)
    graph.add_node("analyze_trust", _trust)
    graph.add_node("assess_risk", _assess)

    graph.set_entry_point("discover_identities")
    graph.add_conditional_edges(
        "discover_identities",
        _has_error,
        {"end": END, "continue": "map_federations"},
    )
    graph.add_edge("map_federations", "detect_misconfigs")
    graph.add_edge("detect_misconfigs", "analyze_trust")
    graph.add_edge("analyze_trust", "assess_risk")
    graph.add_edge("assess_risk", END)

    return graph


def create_cloud_identity_federation_graph(
    idp_clients: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Identity Federation agent graph."""
    toolkit = CloudIdentityFederationToolkit(
        idp_clients=idp_clients,
    )
    return build_graph(toolkit)
