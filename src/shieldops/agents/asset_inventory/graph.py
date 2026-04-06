"""Asset Inventory Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: AssetInventoryToolkit):  # type: ignore[no-untyped-def]
    """Build the asset_inventory agent graph (linear sequence)."""
    return build_linear_graph(
        AssetInventoryState,
        [
            ("discover", discover),
            ("classify", classify),
            ("assign_owners", assign_owners),
            ("assess_risk", assess_risk),
            ("reconcile", reconcile),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


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
