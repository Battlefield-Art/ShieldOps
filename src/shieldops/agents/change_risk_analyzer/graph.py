"""Change Risk Analyzer Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ChangeRiskAnalyzerState
from .nodes import (
    analyze_diff,
    assess_risk,
    collect_change,
    generate_report,
    predict_blast_radius,
    recommend,
)
from .tools import ChangeRiskAnalyzerToolkit


def build_graph(toolkit: ChangeRiskAnalyzerToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Change Risk Analyzer agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect_change(state: Any) -> dict[str, Any]:
        return await collect_change(_to_dict(state), toolkit)

    async def _analyze_diff(state: Any) -> dict[str, Any]:
        return await analyze_diff(_to_dict(state), toolkit)

    async def _assess_risk(state: Any) -> dict[str, Any]:
        return await assess_risk(_to_dict(state), toolkit)

    async def _predict_blast_radius(state: Any) -> dict[str, Any]:
        return await predict_blast_radius(_to_dict(state), toolkit)

    async def _recommend(state: Any) -> dict[str, Any]:
        return await recommend(_to_dict(state), toolkit)

    async def _generate_report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(ChangeRiskAnalyzerState)
    graph.add_node("collect_change", _collect_change)
    graph.add_node("analyze_diff", _analyze_diff)
    graph.add_node("assess_risk", _assess_risk)
    graph.add_node("predict_blast_radius", _predict_blast_radius)
    graph.add_node("recommend", _recommend)
    graph.add_node("generate_report", _generate_report)

    graph.set_entry_point("collect_change")
    graph.add_edge("collect_change", "analyze_diff")
    graph.add_edge("analyze_diff", "assess_risk")
    graph.add_edge("assess_risk", "predict_blast_radius")
    graph.add_edge("predict_blast_radius", "recommend")
    graph.add_edge("recommend", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_change_risk_analyzer_graph(
    git_client: Any | None = None,
    deployment_db: Any | None = None,
    incident_db: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Change Risk Analyzer agent graph with dependencies."""
    toolkit = ChangeRiskAnalyzerToolkit(
        git_client=git_client,
        deployment_db=deployment_db,
        incident_db=incident_db,
    )
    return build_graph(toolkit)
