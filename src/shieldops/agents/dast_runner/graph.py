"""DAST Runner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DASTRunnerState
from .nodes import (
    analyze_responses,
    crawl_application,
    discover_endpoints,
    fuzz_parameters,
    generate_report,
    test_authentication,
)
from .tools import DASTRunnerToolkit


def build_graph(
    toolkit: DASTRunnerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the DAST Runner LangGraph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        if not isinstance(state, dict):
            return dict(state)
        return state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_endpoints(_to_dict(state), toolkit)

    async def _crawl(state: Any) -> dict[str, Any]:
        return await crawl_application(_to_dict(state), toolkit)

    async def _auth(state: Any) -> dict[str, Any]:
        return await test_authentication(_to_dict(state), toolkit)

    async def _fuzz(state: Any) -> dict[str, Any]:
        return await fuzz_parameters(_to_dict(state), toolkit)

    async def _analyze(state: Any) -> dict[str, Any]:
        return await analyze_responses(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(DASTRunnerState)
    graph.add_node("discover_endpoints", _discover)
    graph.add_node("crawl_application", _crawl)
    graph.add_node("test_authentication", _auth)
    graph.add_node("fuzz_parameters", _fuzz)
    graph.add_node("analyze_responses", _analyze)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("discover_endpoints")
    graph.add_edge("discover_endpoints", "crawl_application")
    graph.add_edge("crawl_application", "test_authentication")
    graph.add_edge("test_authentication", "fuzz_parameters")
    graph.add_edge("fuzz_parameters", "analyze_responses")
    graph.add_edge("analyze_responses", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_dast_runner_graph(
    http_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the DAST Runner graph with dependencies."""
    toolkit = DASTRunnerToolkit(http_client=http_client)
    return build_graph(toolkit)
