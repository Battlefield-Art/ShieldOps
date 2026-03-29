"""IaC Security Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import IACScannerState
from .nodes import (
    discover_templates,
    evaluate_policies,
    generate_report,
    parse_resources,
    prioritize_findings,
    scan_misconfigs,
)
from .tools import IACSecurityScannerToolkit


def build_graph(
    toolkit: IACSecurityScannerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the IaC Security Scanner LangGraph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        if not isinstance(state, dict):
            return dict(state)
        return state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_templates(_to_dict(state), toolkit)

    async def _parse(state: Any) -> dict[str, Any]:
        return await parse_resources(_to_dict(state), toolkit)

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_misconfigs(_to_dict(state), toolkit)

    async def _policies(state: Any) -> dict[str, Any]:
        return await evaluate_policies(_to_dict(state), toolkit)

    async def _prioritize(state: Any) -> dict[str, Any]:
        return await prioritize_findings(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(IACScannerState)
    graph.add_node("discover_templates", _discover)
    graph.add_node("parse_resources", _parse)
    graph.add_node("scan_misconfigs", _scan)
    graph.add_node("evaluate_policies", _policies)
    graph.add_node("prioritize", _prioritize)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("discover_templates")
    graph.add_edge("discover_templates", "parse_resources")
    graph.add_edge("parse_resources", "scan_misconfigs")
    graph.add_edge("scan_misconfigs", "evaluate_policies")
    graph.add_edge("evaluate_policies", "prioritize")
    graph.add_edge("prioritize", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_iac_security_scanner_graph(
    git_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the IaC Security Scanner graph with deps."""
    toolkit = IACSecurityScannerToolkit(git_client=git_client)
    return build_graph(toolkit)
