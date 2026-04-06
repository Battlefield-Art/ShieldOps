"""Compliance Auditor Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ComplianceAuditorState
from .nodes import (
    analyze_cloudtrail,
    analyze_gaps,
    collect_evidence,
    generate_report,
    scan_infrastructure,
)
from .tools import ComplianceAuditorToolkit


def create_compliance_auditor_graph(
    toolkit: ComplianceAuditorToolkit | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Compliance Auditor agent graph."""
    if toolkit is None:
        toolkit = ComplianceAuditorToolkit()

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return state  # type: ignore[no-any-return]

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_infrastructure(_to_dict(state), toolkit)

    async def _analyze_cloudtrail(state: Any) -> dict[str, Any]:
        return await analyze_cloudtrail(_to_dict(state), toolkit)

    async def _collect_evidence(state: Any) -> dict[str, Any]:
        return await collect_evidence(_to_dict(state), toolkit)

    async def _analyze_gaps(state: Any) -> dict[str, Any]:
        return await analyze_gaps(_to_dict(state), toolkit)

    async def _generate_report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(ComplianceAuditorState)
    graph.add_node("scan", _scan)
    graph.add_node("analyze_cloudtrail", _analyze_cloudtrail)
    graph.add_node("collect_evidence", _collect_evidence)
    graph.add_node("analyze_gaps", _analyze_gaps)
    graph.add_node("generate_report", _generate_report)

    graph.set_entry_point("scan")
    graph.add_edge("scan", "analyze_cloudtrail")
    graph.add_edge("analyze_cloudtrail", "collect_evidence")
    graph.add_edge("collect_evidence", "analyze_gaps")
    graph.add_edge("analyze_gaps", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
