"""Asset Inventory Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import AssetInventoryState
from .nodes import (
    assess_risk,
    assign_owners,
    classify,
    discover,
    generate_report,
    reconcile,
)
from .tools import AssetInventoryToolkit


def build_graph(
    toolkit: AssetInventoryToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Asset Inventory agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover(_to_dict(state), toolkit)

    async def _classify(state: Any) -> dict[str, Any]:
        return await classify(_to_dict(state), toolkit)

    async def _assign_owners(
        state: Any,
    ) -> dict[str, Any]:
        return await assign_owners(_to_dict(state), toolkit)

    async def _assess_risk(state: Any) -> dict[str, Any]:
        return await assess_risk(_to_dict(state), toolkit)

    async def _reconcile(state: Any) -> dict[str, Any]:
        return await reconcile(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(AssetInventoryState)
    graph.add_node("discover", _discover)
    graph.add_node("classify", _classify)
    graph.add_node("assign_owners", _assign_owners)
    graph.add_node("assess_risk", _assess_risk)
    graph.add_node("reconcile", _reconcile)
    graph.add_node("report", _report)

    graph.set_entry_point("discover")
    graph.add_edge("discover", "classify")
    graph.add_edge("classify", "assign_owners")
    graph.add_edge("assign_owners", "assess_risk")
    graph.add_edge("assess_risk", "reconcile")
    graph.add_edge("reconcile", "report")
    graph.add_edge("report", END)

    return graph


def create_asset_inventory_graph(
    cloud_client: Any | None = None,
    cmdb_client: Any | None = None,
    scanner_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Asset Inventory agent graph with dependencies."""
    toolkit = AssetInventoryToolkit(
        cloud_client=cloud_client,
        cmdb_client=cmdb_client,
        scanner_client=scanner_client,
    )
    return build_graph(toolkit)
