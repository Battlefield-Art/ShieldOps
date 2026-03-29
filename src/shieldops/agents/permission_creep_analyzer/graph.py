"""Permission Creep Analyzer Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.permission_creep_analyzer.models import PermissionCreepAnalyzerState
from shieldops.agents.permission_creep_analyzer.nodes import (
    assess_risk,
    baseline_role,
    collect_permissions,
    detect_creep,
    recommend,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "permission_creep_analyzer"


def _check_error(state: PermissionCreepAnalyzerState) -> str:
    return "report" if state.error else "next"


def create_permission_creep_analyzer_graph() -> StateGraph:
    """Build the Permission Creep Analyzer workflow."""
    graph = StateGraph(PermissionCreepAnalyzerState)

    graph.add_node(
        "collect_permissions",
        traced_node(f"{_AGENT}.collect_permissions", _AGENT)(collect_permissions),
    )
    graph.add_node(
        "baseline_role",
        traced_node(f"{_AGENT}.baseline_role", _AGENT)(baseline_role),
    )
    graph.add_node(
        "detect_creep",
        traced_node(f"{_AGENT}.detect_creep", _AGENT)(detect_creep),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_permissions")

    graph.add_conditional_edges(
        "collect_permissions",
        _check_error,
        {"next": "baseline_role", "report": "report"},
    )
    graph.add_conditional_edges(
        "baseline_role",
        _check_error,
        {"next": "detect_creep", "report": "report"},
    )
    graph.add_conditional_edges(
        "detect_creep",
        _check_error,
        {"next": "assess_risk", "report": "report"},
    )
    graph.add_conditional_edges(
        "assess_risk",
        _check_error,
        {"next": "recommend", "report": "report"},
    )
    graph.add_edge("recommend", "report")
    graph.add_edge("report", END)

    return graph
