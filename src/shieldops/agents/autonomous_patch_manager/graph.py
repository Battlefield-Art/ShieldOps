"""LangGraph workflow for the Autonomous Patch Manager Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.autonomous_patch_manager.models import (
    AutonomousPatchManagerState,
)
from shieldops.agents.autonomous_patch_manager.nodes import (
    assess_patches,
    execute_patches,
    generate_report,
    scan_inventory,
    schedule_deployment,
    validate_results,
)
from shieldops.agents.tracing import traced_node

_AGENT = "autonomous_patch_manager"


def _should_schedule(state: AutonomousPatchManagerState) -> str:
    if state.error:
        return "generate_report"
    if state.patch_assessments:
        return "schedule_deployment"
    return "generate_report"


def _should_validate(state: AutonomousPatchManagerState) -> str:
    if state.execution_results:
        return "validate_results"
    return "generate_report"


def create_autonomous_patch_manager_graph(
    **clients: object,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Autonomous Patch Manager LangGraph."""
    graph = StateGraph(AutonomousPatchManagerState)

    graph.add_node(
        "scan_inventory",
        traced_node(f"{_AGENT}.scan_inventory", _AGENT)(scan_inventory),
    )
    graph.add_node(
        "assess_patches",
        traced_node(f"{_AGENT}.assess_patches", _AGENT)(assess_patches),
    )
    graph.add_node(
        "schedule_deployment",
        traced_node(f"{_AGENT}.schedule_deployment", _AGENT)(schedule_deployment),
    )
    graph.add_node(
        "execute_patches",
        traced_node(f"{_AGENT}.execute_patches", _AGENT)(execute_patches),
    )
    graph.add_node(
        "validate_results",
        traced_node(f"{_AGENT}.validate_results", _AGENT)(validate_results),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("scan_inventory")
    graph.add_edge("scan_inventory", "assess_patches")
    graph.add_conditional_edges(
        "assess_patches",
        _should_schedule,
        {
            "schedule_deployment": "schedule_deployment",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("schedule_deployment", "execute_patches")
    graph.add_conditional_edges(
        "execute_patches",
        _should_validate,
        {
            "validate_results": "validate_results",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("validate_results", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
