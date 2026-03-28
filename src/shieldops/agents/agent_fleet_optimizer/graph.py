"""LangGraph workflow for Agent Fleet Optimizer."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.agent_fleet_optimizer.models import (
    AgentFleetOptimizerState,
)
from shieldops.agents.agent_fleet_optimizer.nodes import (
    analyze_health,
    collect_fleet_status,
    detect_issues,
    optimize_schedules,
    recommend_actions,
    report,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def build_graph(
    toolkit: object | None = None,
) -> StateGraph:
    """Build the Agent Fleet Optimizer workflow.

    Workflow::

        collect_fleet_status -> analyze_health
            -> optimize_schedules -> detect_issues
            -> recommend_actions -> report -> END
    """
    _a = "agent_fleet_optimizer"
    graph = StateGraph(AgentFleetOptimizerState)

    graph.add_node(
        "collect_fleet_status",
        traced_node(f"{_a}.collect_fleet_status", _a)(collect_fleet_status),
    )
    graph.add_node(
        "analyze_health",
        traced_node(f"{_a}.analyze_health", _a)(analyze_health),
    )
    graph.add_node(
        "optimize_schedules",
        traced_node(f"{_a}.optimize_schedules", _a)(optimize_schedules),
    )
    graph.add_node(
        "detect_issues",
        traced_node(f"{_a}.detect_issues", _a)(detect_issues),
    )
    graph.add_node(
        "recommend_actions",
        traced_node(f"{_a}.recommend_actions", _a)(recommend_actions),
    )
    graph.add_node(
        "report",
        traced_node(f"{_a}.report", _a)(report),
    )

    graph.set_entry_point("collect_fleet_status")
    graph.add_edge("collect_fleet_status", "analyze_health")
    graph.add_edge("analyze_health", "optimize_schedules")
    graph.add_edge("optimize_schedules", "detect_issues")
    graph.add_edge("detect_issues", "recommend_actions")
    graph.add_edge("recommend_actions", "report")
    graph.add_edge("report", END)

    return graph


def create_agent_fleet_optimizer_graph() -> StateGraph:
    """Factory to create Fleet Optimizer graph."""
    return build_graph()
