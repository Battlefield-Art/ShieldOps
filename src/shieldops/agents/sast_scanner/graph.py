"""SAST Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SASTScannerState
from .nodes import (
    analyze_dataflow,
    discover_files,
    generate_report,
    parse_ast,
    prioritize,
    scan_patterns,
)
from .tools import SASTScannerToolkit


def build_graph(
    toolkit: SASTScannerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the SAST Scanner LangGraph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        if not isinstance(state, dict):
            return dict(state)
        return state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_files(_to_dict(state), toolkit)

    async def _parse(state: Any) -> dict[str, Any]:
        return await parse_ast(_to_dict(state), toolkit)

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_patterns(_to_dict(state), toolkit)

    async def _dataflow(state: Any) -> dict[str, Any]:
        return await analyze_dataflow(_to_dict(state), toolkit)

    async def _prioritize(state: Any) -> dict[str, Any]:
        return await prioritize(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(SASTScannerState)
    graph.add_node("discover_files", _discover)
    graph.add_node("parse_ast", _parse)
    graph.add_node("scan_patterns", _scan)
    graph.add_node("analyze_dataflow", _dataflow)
    graph.add_node("prioritize", _prioritize)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("discover_files")
    graph.add_edge("discover_files", "parse_ast")
    graph.add_edge("parse_ast", "scan_patterns")
    graph.add_edge("scan_patterns", "analyze_dataflow")
    graph.add_edge("analyze_dataflow", "prioritize")
    graph.add_edge("prioritize", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_sast_scanner_graph(
    git_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the SAST Scanner graph with dependencies."""
    toolkit = SASTScannerToolkit(git_client=git_client)
    return build_graph(toolkit)
