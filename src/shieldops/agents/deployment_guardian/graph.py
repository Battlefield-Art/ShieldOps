"""Deployment Guardian Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.deployment_guardian.models import (
    DeploymentGuardianState,
)
from shieldops.agents.deployment_guardian.nodes import (
    analyze_changes,
    approve_deployment,
    monitor_rollout,
    report,
    run_preflight,
    validate_security,
)
from shieldops.agents.tracing import traced_node

_AGENT = "deployment_guardian"


def _check_error(
    state: DeploymentGuardianState,
) -> str:
    return "report" if state.error else "next"


def create_deployment_guardian_graph() -> StateGraph:
    """Build the Deployment Guardian workflow."""
    graph = StateGraph(DeploymentGuardianState)

    graph.add_node(
        "analyze_changes",
        traced_node("dg.analyze_changes", _AGENT)(analyze_changes),
    )
    graph.add_node(
        "run_preflight",
        traced_node("dg.run_preflight", _AGENT)(run_preflight),
    )
    graph.add_node(
        "validate_security",
        traced_node("dg.validate_security", _AGENT)(validate_security),
    )
    graph.add_node(
        "approve_deployment",
        traced_node("dg.approve_deployment", _AGENT)(approve_deployment),
    )
    graph.add_node(
        "monitor_rollout",
        traced_node("dg.monitor_rollout", _AGENT)(monitor_rollout),
    )
    graph.add_node(
        "report",
        traced_node("dg.report", _AGENT)(report),
    )

    graph.set_entry_point("analyze_changes")

    graph.add_conditional_edges(
        "analyze_changes",
        _check_error,
        {
            "report": "report",
            "next": "run_preflight",
        },
    )
    graph.add_conditional_edges(
        "run_preflight",
        _check_error,
        {
            "report": "report",
            "next": "validate_security",
        },
    )
    graph.add_conditional_edges(
        "validate_security",
        _check_error,
        {
            "report": "report",
            "next": "approve_deployment",
        },
    )
    graph.add_conditional_edges(
        "approve_deployment",
        _check_error,
        {
            "report": "report",
            "next": "monitor_rollout",
        },
    )
    graph.add_edge("monitor_rollout", "report")
    graph.add_edge("report", END)

    return graph
