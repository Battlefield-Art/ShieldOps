"""OTel Semantic Conventions Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import OTelSemanticState
from .nodes import (
    analyze_violations,
    generate_fixes,
    load_rules,
    scan_services,
)
from .tools import OTelSemanticToolkit


def build_graph(toolkit: OTelSemanticToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the OTel Semantic Conventions agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return state  # type: ignore[no-any-return]

    async def _load_rules(state: Any) -> dict[str, Any]:
        return await load_rules(_to_dict(state), toolkit)

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_services(_to_dict(state), toolkit)

    async def _analyze(state: Any) -> dict[str, Any]:
        return await analyze_violations(_to_dict(state), toolkit)

    async def _fixes(state: Any) -> dict[str, Any]:
        return await generate_fixes(_to_dict(state), toolkit)

    graph = StateGraph(OTelSemanticState)
    graph.add_node("load_rules", _load_rules)
    graph.add_node("scan", _scan)
    graph.add_node("analyze", _analyze)
    graph.add_node("generate_fixes", _fixes)

    graph.set_entry_point("load_rules")
    graph.add_edge("load_rules", "scan")
    graph.add_edge("scan", "analyze")
    graph.add_edge("analyze", "generate_fixes")
    graph.add_edge("generate_fixes", END)

    return graph


def create_otel_semantic_graph(
    telemetry_client: Any | None = None,
    repository: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create and return the OTel Semantic Conventions graph.

    This is the main public entry point exported from __init__.py.
    """
    toolkit = OTelSemanticToolkit(
        telemetry_client=telemetry_client,
        repository=repository,
    )
    return build_graph(toolkit)
