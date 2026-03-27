"""LangGraph workflow for the Patch Orchestrator Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.patch_orchestrator.models import (
    PatchOrchestratorState,
)
from shieldops.agents.patch_orchestrator.nodes import (
    assess_patches,
    deploy_patches,
    generate_report,
    inventory_systems,
    prioritize_deployment,
    verify_success,
)
from shieldops.agents.tracing import traced_node


def route_after_deploy(
    state: PatchOrchestratorState,
) -> str:
    """Route based on deployment results."""
    if state.error:
        return "generate_report"
    return "verify_success"


def build_graph() -> StateGraph:
    """Build the Patch Orchestrator LangGraph."""
    _a = "patch_orchestrator"
    graph = StateGraph(PatchOrchestratorState)

    graph.add_node(
        "inventory_systems",
        traced_node("patch.inventory", _a)(inventory_systems),
    )
    graph.add_node(
        "assess_patches",
        traced_node("patch.assess", _a)(assess_patches),
    )
    graph.add_node(
        "prioritize_deployment",
        traced_node("patch.prioritize", _a)(prioritize_deployment),
    )
    graph.add_node(
        "deploy_patches",
        traced_node("patch.deploy", _a)(deploy_patches),
    )
    graph.add_node(
        "verify_success",
        traced_node("patch.verify", _a)(verify_success),
    )
    graph.add_node(
        "generate_report",
        traced_node("patch.report", _a)(generate_report),
    )

    graph.set_entry_point("inventory_systems")
    graph.add_edge("inventory_systems", "assess_patches")
    graph.add_edge("assess_patches", "prioritize_deployment")
    graph.add_edge("prioritize_deployment", "deploy_patches")
    graph.add_conditional_edges(
        "deploy_patches",
        route_after_deploy,
        {
            "verify_success": "verify_success",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("verify_success", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_patch_orchestrator_graph(
    **clients: object,
) -> StateGraph:
    """Factory to create a Patch Orchestrator graph."""
    return build_graph()
