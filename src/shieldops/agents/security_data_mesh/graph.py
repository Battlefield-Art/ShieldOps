"""Security Data Mesh Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

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


def build_graph(
    toolkit: SecurityDataMeshToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Data Mesh graph.

    Flow:
        discover_domains -> map_data_products
        -> assess_quality -> federate_queries
        -> generate_insights -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_domains(
            _to_dict(state),
            toolkit,
        )

    async def _map(
        state: Any,
    ) -> dict[str, Any]:
        return await map_data_products(
            _to_dict(state),
            toolkit,
        )

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_quality(
            _to_dict(state),
            toolkit,
        )

    async def _federate(
        state: Any,
    ) -> dict[str, Any]:
        return await federate_queries(
            _to_dict(state),
            toolkit,
        )

    async def _insights(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_insights(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(SecurityDataMeshState)
    graph.add_node("discover_domains", _discover)
    graph.add_node("map_data_products", _map)
    graph.add_node("assess_quality", _assess)
    graph.add_node("federate_queries", _federate)
    graph.add_node("generate_insights", _insights)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_domains")
    graph.add_edge(
        "discover_domains",
        "map_data_products",
    )
    graph.add_edge(
        "map_data_products",
        "assess_quality",
    )
    graph.add_edge(
        "assess_quality",
        "federate_queries",
    )
    graph.add_edge(
        "federate_queries",
        "generate_insights",
    )
    graph.add_edge(
        "generate_insights",
        "report",
    )
    graph.add_edge("report", END)

    return graph


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
