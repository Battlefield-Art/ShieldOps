"""IAM Policy Analyzer Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import IAMPolicyAnalyzerState
from .nodes import (
    analyze_permissions,
    collect_policies,
    detect_overprivilege,
    find_unused,
    generate_report,
    recommend_fixes,
)
from .tools import IAMPolicyAnalyzerToolkit


def _has_overprivilege(state: Any) -> str:
    """Route based on whether over-privilege was detected."""
    if isinstance(state, dict):
        alerts = state.get("overprivilege_alerts", [])
    else:
        alerts = getattr(state, "overprivilege_alerts", [])

    if alerts:
        return "find_unused"
    return "generate_report"


def build_graph(
    toolkit: IAMPolicyAnalyzerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the IAM Policy Analyzer agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(state: Any) -> dict[str, Any]:
        return await collect_policies(_to_dict(state), toolkit)

    async def _analyze(state: Any) -> dict[str, Any]:
        return await analyze_permissions(_to_dict(state), toolkit)

    async def _overprivilege(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_overprivilege(_to_dict(state), toolkit)

    async def _unused(state: Any) -> dict[str, Any]:
        return await find_unused(_to_dict(state), toolkit)

    async def _recommend(state: Any) -> dict[str, Any]:
        return await recommend_fixes(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(IAMPolicyAnalyzerState)

    # Add nodes
    graph.add_node("collect_policies", _collect)
    graph.add_node("analyze_permissions", _analyze)
    graph.add_node("detect_overprivilege", _overprivilege)
    graph.add_node("find_unused", _unused)
    graph.add_node("recommend_fixes", _recommend)
    graph.add_node("generate_report", _report)

    # Linear flow: collect -> analyze -> detect_overprivilege
    graph.set_entry_point("collect_policies")
    graph.add_edge("collect_policies", "analyze_permissions")
    graph.add_edge("analyze_permissions", "detect_overprivilege")

    # Conditional: if over-privilege found -> find unused
    # -> recommend -> report; else skip to report
    graph.add_conditional_edges(
        "detect_overprivilege",
        _has_overprivilege,
        {
            "find_unused": "find_unused",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("find_unused", "recommend_fixes")
    graph.add_edge("recommend_fixes", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_iam_policy_analyzer_graph(
    iam_clients: Any | None = None,
    usage_tracker: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the IAM Policy Analyzer graph with deps."""
    toolkit = IAMPolicyAnalyzerToolkit(
        iam_clients=iam_clients,
        usage_tracker=usage_tracker,
    )
    return build_graph(toolkit)
