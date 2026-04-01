"""LangGraph workflow for the Autonomous Ops Controller."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.autonomous_ops_controller.models import (
    AutonomousOpsControllerState,
)
from shieldops.agents.autonomous_ops_controller.nodes import (
    assess_fleet,
    dispatch_tasks,
    evaluate_outcomes,
    generate_report,
    monitor_execution,
    plan_operations,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()

_AGENT = "autonomous_ops_controller"


def should_dispatch_tasks(
    state: AutonomousOpsControllerState,
) -> str:
    """Route: dispatch tasks if operations planned, else skip to report."""
    if state.error:
        return "generate_report"
    if state.operation_plans:
        return "dispatch_tasks"
    return "generate_report"


def should_evaluate_outcomes(
    state: AutonomousOpsControllerState,
) -> str:
    """Route: evaluate outcomes if tasks completed."""
    if state.error:
        return "generate_report"
    if state.execution_statuses:
        return "evaluate_outcomes"
    return "generate_report"


def create_autonomous_ops_controller_graph() -> (
    StateGraph  # type: ignore[type-arg]
):
    """Build the Autonomous Ops Controller LangGraph workflow.

    Workflow:
        assess_fleet
        -> plan_operations
        -> [plans? -> dispatch_tasks -> monitor_execution]
        -> [statuses? -> evaluate_outcomes]
        -> generate_report
        -> END
    """
    graph = StateGraph(AutonomousOpsControllerState)

    # Add nodes with OTEL tracing
    graph.add_node(
        "assess_fleet",
        traced_node(
            f"{_AGENT}.assess_fleet",
            _AGENT,
        )(assess_fleet),
    )
    graph.add_node(
        "plan_operations",
        traced_node(
            f"{_AGENT}.plan_operations",
            _AGENT,
        )(plan_operations),
    )
    graph.add_node(
        "dispatch_tasks",
        traced_node(
            f"{_AGENT}.dispatch_tasks",
            _AGENT,
        )(dispatch_tasks),
    )
    graph.add_node(
        "monitor_execution",
        traced_node(
            f"{_AGENT}.monitor_execution",
            _AGENT,
        )(monitor_execution),
    )
    graph.add_node(
        "evaluate_outcomes",
        traced_node(
            f"{_AGENT}.evaluate_outcomes",
            _AGENT,
        )(evaluate_outcomes),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("assess_fleet")
    graph.add_edge("assess_fleet", "plan_operations")
    graph.add_conditional_edges(
        "plan_operations",
        should_dispatch_tasks,
        {
            "dispatch_tasks": "dispatch_tasks",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("dispatch_tasks", "monitor_execution")
    graph.add_conditional_edges(
        "monitor_execution",
        should_evaluate_outcomes,
        {
            "evaluate_outcomes": "evaluate_outcomes",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("evaluate_outcomes", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
