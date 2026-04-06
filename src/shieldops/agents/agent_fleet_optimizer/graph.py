"""LangGraph workflow for Agent Fleet Optimizer."""

from __future__ import annotations

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import AgentFleetOptimizerState
from .nodes import (
    analyze_health,
    collect_fleet_status,
    detect_issues,
    optimize_schedules,
    recommend_actions,
    report,
)


def build_graph(toolkit: object = None):  # type: ignore[no-untyped-def]
    """Build the agent_fleet_optimizer agent graph (linear sequence)."""
    return build_linear_graph(
        AgentFleetOptimizerState,
        [
            ("collect_fleet_status", collect_fleet_status),
            ("analyze_health", analyze_health),
            ("optimize_schedules", optimize_schedules),
            ("detect_issues", detect_issues),
            ("recommend_actions", recommend_actions),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_agent_fleet_optimizer_graph() -> StateGraph:
    """Factory to create Fleet Optimizer graph."""
    return build_graph()
