"""LangGraph workflow definition for the Autonomous
Patch Manager Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.autonomous_patch_manager.models import (
    AutonomousPatchManagerState,
)
from shieldops.agents.autonomous_patch_manager.nodes import (
    assess_risk,
    check_patches,
    deploy_patches,
    generate_report,
    scan_inventory,
    schedule_deployment,
)
from shieldops.agents.tracing import traced_node

_AGENT = "autonomous_patch_manager"


def _should_deploy(
    state: AutonomousPatchManagerState,
) -> str:
    """Route after scheduling: deploy if auto_deploy is
    enabled and patches exist, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.auto_deploy and state.schedules:
        return "deploy_patches"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Autonomous Patch Manager LangGraph
    workflow.

    Workflow:
        scan_inventory -> check_patches -> assess_risk
            -> schedule_deployment
            -> [auto_deploy? -> deploy_patches]
            -> generate_report -> END
    """
    graph = StateGraph(AutonomousPatchManagerState)

    graph.add_node(
        "scan_inventory",
        traced_node(f"{_AGENT}.scan_inventory", _AGENT)(scan_inventory),
    )
    graph.add_node(
        "check_patches",
        traced_node(f"{_AGENT}.check_patches", _AGENT)(check_patches),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "schedule_deployment",
        traced_node(f"{_AGENT}.schedule_deployment", _AGENT)(schedule_deployment),
    )
    graph.add_node(
        "deploy_patches",
        traced_node(f"{_AGENT}.deploy_patches", _AGENT)(deploy_patches),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("scan_inventory")
    graph.add_edge("scan_inventory", "check_patches")
    graph.add_edge("check_patches", "assess_risk")
    graph.add_edge("assess_risk", "schedule_deployment")
    graph.add_conditional_edges(
        "schedule_deployment",
        _should_deploy,
        {
            "deploy_patches": "deploy_patches",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("deploy_patches", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_autonomous_patch_manager_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create an Autonomous Patch Manager
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
