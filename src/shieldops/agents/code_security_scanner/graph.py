"""Code Security Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CodeSecurityScannerState
from .nodes import (
    discover_repositories,
    generate_report,
    prioritize_findings,
    scan_application_code,
    scan_dependencies,
    scan_iac,
)
from .tools import CodeSecurityScannerToolkit


def build_graph(
    toolkit: CodeSecurityScannerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Code Security Scanner LangGraph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        if not isinstance(state, dict):
            return dict(state)
        return state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_repositories(_to_dict(state), toolkit)

    async def _scan_iac(state: Any) -> dict[str, Any]:
        return await scan_iac(_to_dict(state), toolkit)

    async def _scan_deps(state: Any) -> dict[str, Any]:
        return await scan_dependencies(_to_dict(state), toolkit)

    async def _scan_code(state: Any) -> dict[str, Any]:
        return await scan_application_code(_to_dict(state), toolkit)

    async def _prioritize(state: Any) -> dict[str, Any]:
        return await prioritize_findings(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(CodeSecurityScannerState)
    graph.add_node("discover_repositories", _discover)
    graph.add_node("scan_iac", _scan_iac)
    graph.add_node("scan_dependencies", _scan_deps)
    graph.add_node("scan_application_code", _scan_code)
    graph.add_node("prioritize_findings", _prioritize)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("discover_repositories")
    graph.add_edge("discover_repositories", "scan_iac")
    graph.add_edge("scan_iac", "scan_dependencies")
    graph.add_edge("scan_dependencies", "scan_application_code")
    graph.add_edge("scan_application_code", "prioritize_findings")
    graph.add_edge("prioritize_findings", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_code_security_scanner_graph(
    git_client: Any | None = None,
    registry_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Code Security Scanner graph with deps."""
    toolkit = CodeSecurityScannerToolkit(
        git_client=git_client,
        registry_client=registry_client,
    )
    return build_graph(toolkit)
