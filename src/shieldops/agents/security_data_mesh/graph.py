"""Security Data Mesh Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SecurityDataMeshState
from .nodes import (
    assess_quality,
    discover_domains,
    federate_queries,
    generate_insights,
    generate_report,
    map_data_products,
)
from .tools import SecurityDataMeshToolkit


def build_graph(toolkit: SecurityDataMeshToolkit):  # type: ignore[no-untyped-def]
    """Build the security_data_mesh agent graph (linear sequence)."""
    return build_linear_graph(
        SecurityDataMeshState,
        [
            ("discover_domains", discover_domains),
            ("map_data_products", map_data_products),
            ("assess_quality", assess_quality),
            ("federate_queries", federate_queries),
            ("generate_insights", generate_insights),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_security_data_mesh_graph(
    mesh_catalog: Any | None = None,
    query_engine: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security Data Mesh graph."""
    toolkit = SecurityDataMeshToolkit(
        mesh_catalog=mesh_catalog,
        query_engine=query_engine,
    )
    return build_graph(toolkit)
