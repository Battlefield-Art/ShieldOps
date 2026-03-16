"""Automated Security Testing Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecurityTestingState
from .nodes import (
    analyze_findings,
    define_scope,
    execute_scans,
    generate_report,
)
from .tools import SecurityTestingToolkit


def build_graph(toolkit: SecurityTestingToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Automated Security Testing agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scope(state: Any) -> dict[str, Any]:
        return await define_scope(_to_dict(state), toolkit)

    async def _scan(state: Any) -> dict[str, Any]:
        return await execute_scans(_to_dict(state), toolkit)

    async def _analyze(state: Any) -> dict[str, Any]:
        return await analyze_findings(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(SecurityTestingState)
    graph.add_node("define_scope", _scope)
    graph.add_node("execute_scans", _scan)
    graph.add_node("analyze_findings", _analyze)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("define_scope")
    graph.add_edge("define_scope", "execute_scans")
    graph.add_edge("execute_scans", "analyze_findings")
    graph.add_edge("analyze_findings", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_testing_graph(
    scanner_client: Any | None = None,
    config_client: Any | None = None,
    credential_store: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Automated Security Testing agent graph with dependencies."""
    toolkit = SecurityTestingToolkit(
        scanner_client=scanner_client,
        config_client=config_client,
        credential_store=credential_store,
    )
    return build_graph(toolkit)
