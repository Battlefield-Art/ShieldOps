"""SCA Dependency Checker Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SCADependencyCheckerState
from .nodes import (
    check_licenses,
    discover_manifests,
    generate_report,
    match_cves,
    parse_dependencies,
    prioritize_findings,
)
from .tools import SCADependencyCheckerToolkit


def build_graph(
    toolkit: SCADependencyCheckerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the SCA Dependency Checker LangGraph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        if not isinstance(state, dict):
            return dict(state)
        return state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_manifests(_to_dict(state), toolkit)

    async def _parse(state: Any) -> dict[str, Any]:
        return await parse_dependencies(_to_dict(state), toolkit)

    async def _match(state: Any) -> dict[str, Any]:
        return await match_cves(_to_dict(state), toolkit)

    async def _licenses(state: Any) -> dict[str, Any]:
        return await check_licenses(_to_dict(state), toolkit)

    async def _prioritize(state: Any) -> dict[str, Any]:
        return await prioritize_findings(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(SCADependencyCheckerState)
    graph.add_node("discover_manifests", _discover)
    graph.add_node("parse_dependencies", _parse)
    graph.add_node("match_cves", _match)
    graph.add_node("check_licenses", _licenses)
    graph.add_node("prioritize", _prioritize)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("discover_manifests")
    graph.add_edge("discover_manifests", "parse_dependencies")
    graph.add_edge("parse_dependencies", "match_cves")
    graph.add_edge("match_cves", "check_licenses")
    graph.add_edge("check_licenses", "prioritize")
    graph.add_edge("prioritize", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_sca_dependency_checker_graph(
    registry_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the SCA Dependency Checker graph with deps."""
    toolkit = SCADependencyCheckerToolkit(
        registry_client=registry_client,
    )
    return build_graph(toolkit)
