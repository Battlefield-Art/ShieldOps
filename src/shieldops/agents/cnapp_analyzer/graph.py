"""CNAPP Analyzer Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CNAPPAnalyzerState
from .nodes import (
    analyze_identity_entitlements,
    assess_workload_protection,
    correlate_risks,
    generate_report,
    scan_cloud_posture,
    scan_code_security,
)
from .tools import CNAPPAnalyzerToolkit


def build_graph(
    toolkit: CNAPPAnalyzerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the CNAPP Analyzer agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan_posture(
        state: Any,
    ) -> dict[str, Any]:
        return await scan_cloud_posture(_to_dict(state), toolkit)

    async def _assess_workload(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_workload_protection(_to_dict(state), toolkit)

    async def _analyze_entitlements(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_identity_entitlements(_to_dict(state), toolkit)

    async def _scan_code(
        state: Any,
    ) -> dict[str, Any]:
        return await scan_code_security(_to_dict(state), toolkit)

    async def _correlate(
        state: Any,
    ) -> dict[str, Any]:
        return await correlate_risks(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(CNAPPAnalyzerState)

    # Add nodes
    graph.add_node("scan_cloud_posture", _scan_posture)
    graph.add_node("assess_workload_protection", _assess_workload)
    graph.add_node(
        "analyze_identity_entitlements",
        _analyze_entitlements,
    )
    graph.add_node("scan_code_security", _scan_code)
    graph.add_node("correlate_risks", _correlate)
    graph.add_node("generate_report", _report)

    # Linear flow through all CNAPP domains
    graph.set_entry_point("scan_cloud_posture")
    graph.add_edge(
        "scan_cloud_posture",
        "assess_workload_protection",
    )
    graph.add_edge(
        "assess_workload_protection",
        "analyze_identity_entitlements",
    )
    graph.add_edge(
        "analyze_identity_entitlements",
        "scan_code_security",
    )
    graph.add_edge("scan_code_security", "correlate_risks")
    graph.add_edge("correlate_risks", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_cnapp_analyzer_graph(
    cloud_clients: Any | None = None,
    workload_scanner: Any | None = None,
    identity_analyzer: Any | None = None,
    code_scanner: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the CNAPP Analyzer graph with deps."""
    toolkit = CNAPPAnalyzerToolkit(
        cloud_clients=cloud_clients,
        workload_scanner=workload_scanner,
        identity_analyzer=identity_analyzer,
        code_scanner=code_scanner,
    )
    return build_graph(toolkit)
