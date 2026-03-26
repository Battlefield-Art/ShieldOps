"""Data Resilience Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DataResilienceState
from .nodes import (
    assess_protection,
    detect_anomalies,
    enforce_immutability,
    generate_report,
    inventory_data_assets,
    validate_recovery,
)
from .tools import DataResilienceToolkit


def _has_anomalies(state: Any) -> str:
    """Route based on whether anomalies were found."""
    if hasattr(state, "model_dump"):
        data = state.model_dump()
    elif isinstance(state, dict):
        data = state
    else:
        data = dict(state)

    anomalies = data.get("anomalies_detected", [])
    if anomalies:
        return "enforce_immutability"
    return "validate_recovery"


def build_graph(
    toolkit: DataResilienceToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Data Resilience agent graph.

    Flow:
        inventory_data_assets -> assess_protection
            -> detect_anomalies
            --(anomalies)--> enforce_immutability
                -> validate_recovery -> generate_report
            --(clean)------> validate_recovery
                -> generate_report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _inventory(
        state: Any,
    ) -> dict[str, Any]:
        return await inventory_data_assets(_to_dict(state), toolkit)

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_protection(_to_dict(state), toolkit)

    async def _anomalies(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_anomalies(_to_dict(state), toolkit)

    async def _enforce(
        state: Any,
    ) -> dict[str, Any]:
        return await enforce_immutability(_to_dict(state), toolkit)

    async def _recovery(
        state: Any,
    ) -> dict[str, Any]:
        return await validate_recovery(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(DataResilienceState)
    graph.add_node("inventory_data_assets", _inventory)
    graph.add_node("assess_protection", _assess)
    graph.add_node("detect_anomalies", _anomalies)
    graph.add_node("enforce_immutability", _enforce)
    graph.add_node("validate_recovery", _recovery)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("inventory_data_assets")
    graph.add_edge("inventory_data_assets", "assess_protection")
    graph.add_edge("assess_protection", "detect_anomalies")

    graph.add_conditional_edges(
        "detect_anomalies",
        _has_anomalies,
        {
            "enforce_immutability": ("enforce_immutability"),
            "validate_recovery": "validate_recovery",
        },
    )

    graph.add_edge("enforce_immutability", "validate_recovery")
    graph.add_edge("validate_recovery", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_data_resilience_graph(
    storage_client: Any | None = None,
    cloud_provider: Any | None = None,
    backup_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Data Resilience agent graph."""
    toolkit = DataResilienceToolkit(
        storage_client=storage_client,
        cloud_provider=cloud_provider,
        backup_api=backup_api,
    )
    return build_graph(toolkit)
