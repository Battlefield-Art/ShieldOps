"""LangGraph workflow for the Deception Mesh Controller."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.deception_mesh_controller.models import (
    DeceptionMeshControllerState,
)
from shieldops.agents.deception_mesh_controller.nodes import (
    analyze_attacker,
    correlate_intel,
    deploy_decoys,
    generate_report,
    monitor_interactions,
    plan_deployment,
)
from shieldops.agents.tracing import traced_node

_AGENT = "deception_mesh_controller"


def _should_analyze(
    state: DeceptionMeshControllerState,
) -> str:
    if state.error:
        return "generate_report"
    if state.interactions:
        return "analyze_attacker"
    return "generate_report"


def _should_correlate(
    state: DeceptionMeshControllerState,
) -> str:
    if state.attacker_profiles:
        return "correlate_intel"
    return "generate_report"


def create_deception_mesh_controller_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Deception Mesh Controller LangGraph.

    Workflow:
        plan_deployment -> deploy_decoys
          -> monitor_interactions
          -> [has_interactions?] -> analyze_attacker
          -> [has_profiles?] -> correlate_intel
          -> generate_report
    """
    graph = StateGraph(DeceptionMeshControllerState)

    graph.add_node(
        "plan_deployment",
        traced_node(f"{_AGENT}.plan_deployment", _AGENT)(
            plan_deployment,
        ),
    )
    graph.add_node(
        "deploy_decoys",
        traced_node(f"{_AGENT}.deploy_decoys", _AGENT)(
            deploy_decoys,
        ),
    )
    graph.add_node(
        "monitor_interactions",
        traced_node(
            f"{_AGENT}.monitor_interactions",
            _AGENT,
        )(monitor_interactions),
    )
    graph.add_node(
        "analyze_attacker",
        traced_node(f"{_AGENT}.analyze_attacker", _AGENT)(
            analyze_attacker,
        ),
    )
    graph.add_node(
        "correlate_intel",
        traced_node(f"{_AGENT}.correlate_intel", _AGENT)(
            correlate_intel,
        ),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(
            generate_report,
        ),
    )

    graph.set_entry_point("plan_deployment")
    graph.add_edge("plan_deployment", "deploy_decoys")
    graph.add_edge("deploy_decoys", "monitor_interactions")
    graph.add_conditional_edges(
        "monitor_interactions",
        _should_analyze,
        {
            "analyze_attacker": "analyze_attacker",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "analyze_attacker",
        _should_correlate,
        {
            "correlate_intel": "correlate_intel",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("correlate_intel", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
