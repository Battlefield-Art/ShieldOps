"""Compliance Reporter Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ComplianceReporterState
from .nodes import (
    assess_controls,
    collect_evidence,
    deliver,
    generate_report,
    package_artifacts,
    select_framework,
)
from .tools import ComplianceReporterToolkit


def create_compliance_reporter_graph(
    evidence_store: Any | None = None,
    policy_engine: Any | None = None,
    delivery_service: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Compliance Reporter agent graph.

    Args:
        evidence_store: Optional backend for evidence collection.
        policy_engine: Optional policy engine for control assessment.
        delivery_service: Optional service for report delivery.

    Returns:
        Compiled LangGraph StateGraph.
    """
    toolkit = ComplianceReporterToolkit(
        evidence_store=evidence_store,
        policy_engine=policy_engine,
        delivery_service=delivery_service,
    )

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return state  # type: ignore[no-any-return]

    async def _select_framework(state: Any) -> dict[str, Any]:
        return await select_framework(_to_dict(state), toolkit)

    async def _collect_evidence(state: Any) -> dict[str, Any]:
        return await collect_evidence(_to_dict(state), toolkit)

    async def _assess_controls(state: Any) -> dict[str, Any]:
        return await assess_controls(_to_dict(state), toolkit)

    async def _generate_report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    async def _package_artifacts(state: Any) -> dict[str, Any]:
        return await package_artifacts(_to_dict(state), toolkit)

    async def _deliver(state: Any) -> dict[str, Any]:
        return await deliver(_to_dict(state), toolkit)

    graph = StateGraph(ComplianceReporterState)
    graph.add_node("select_framework", _select_framework)
    graph.add_node("collect_evidence", _collect_evidence)
    graph.add_node("assess_controls", _assess_controls)
    graph.add_node("generate_report", _generate_report)
    graph.add_node("package_artifacts", _package_artifacts)
    graph.add_node("deliver", _deliver)

    graph.set_entry_point("select_framework")
    graph.add_edge("select_framework", "collect_evidence")
    graph.add_edge("collect_evidence", "assess_controls")
    graph.add_edge("assess_controls", "generate_report")
    graph.add_edge("generate_report", "package_artifacts")
    graph.add_edge("package_artifacts", "deliver")
    graph.add_edge("deliver", END)

    return graph
