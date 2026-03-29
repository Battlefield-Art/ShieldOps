"""Container Image Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ContainerImageScannerState
from .nodes import (
    analyze_layers,
    check_compliance,
    discover_images,
    generate_report,
    prioritize_findings,
    scan_vulnerabilities,
)
from .tools import ContainerImageScannerToolkit


def build_graph(
    toolkit: ContainerImageScannerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Container Image Scanner LangGraph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        if not isinstance(state, dict):
            return dict(state)
        return state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_images(_to_dict(state), toolkit)

    async def _layers(state: Any) -> dict[str, Any]:
        return await analyze_layers(_to_dict(state), toolkit)

    async def _vulns(state: Any) -> dict[str, Any]:
        return await scan_vulnerabilities(_to_dict(state), toolkit)

    async def _compliance(state: Any) -> dict[str, Any]:
        return await check_compliance(_to_dict(state), toolkit)

    async def _prioritize(state: Any) -> dict[str, Any]:
        return await prioritize_findings(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(ContainerImageScannerState)
    graph.add_node("discover_images", _discover)
    graph.add_node("analyze_layers", _layers)
    graph.add_node("scan_vulnerabilities", _vulns)
    graph.add_node("check_compliance", _compliance)
    graph.add_node("prioritize", _prioritize)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("discover_images")
    graph.add_edge("discover_images", "analyze_layers")
    graph.add_edge("analyze_layers", "scan_vulnerabilities")
    graph.add_edge("scan_vulnerabilities", "check_compliance")
    graph.add_edge("check_compliance", "prioritize")
    graph.add_edge("prioritize", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_container_image_scanner_graph(
    registry_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Container Image Scanner graph with deps."""
    toolkit = ContainerImageScannerToolkit(
        registry_client=registry_client,
    )
    return build_graph(toolkit)
