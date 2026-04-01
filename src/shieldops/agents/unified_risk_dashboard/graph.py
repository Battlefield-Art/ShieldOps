"""LangGraph workflow for the Unified Risk Dashboard."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node
from shieldops.agents.unified_risk_dashboard.models import (
    UnifiedRiskDashboardState,
)
from shieldops.agents.unified_risk_dashboard.nodes import (
    aggregate_risks,
    calculate_posture,
    collect_risk_signals,
    generate_report,
    normalize_scores,
    prioritize_actions,
)

logger = structlog.get_logger()

_AGENT = "unified_risk_dashboard"


def _check_error(
    state: UnifiedRiskDashboardState,
) -> str:
    """Route to report on error, otherwise continue."""
    if state.error:
        return "generate_report"
    return "next"


def create_unified_risk_dashboard_graph() -> (
    StateGraph  # type: ignore[type-arg]
):
    """Build the Unified Risk Dashboard LangGraph workflow.

    Workflow:
        collect_risk_signals
        -> normalize_scores
        -> aggregate_risks
        -> calculate_posture
        -> prioritize_actions
        -> generate_report
        -> END
    """
    graph = StateGraph(UnifiedRiskDashboardState)

    # Add nodes with OTEL tracing
    graph.add_node(
        "collect_risk_signals",
        traced_node(
            f"{_AGENT}.collect_risk_signals",
            _AGENT,
        )(collect_risk_signals),
    )
    graph.add_node(
        "normalize_scores",
        traced_node(
            f"{_AGENT}.normalize_scores",
            _AGENT,
        )(normalize_scores),
    )
    graph.add_node(
        "aggregate_risks",
        traced_node(
            f"{_AGENT}.aggregate_risks",
            _AGENT,
        )(aggregate_risks),
    )
    graph.add_node(
        "calculate_posture",
        traced_node(
            f"{_AGENT}.calculate_posture",
            _AGENT,
        )(calculate_posture),
    )
    graph.add_node(
        "prioritize_actions",
        traced_node(
            f"{_AGENT}.prioritize_actions",
            _AGENT,
        )(prioritize_actions),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("collect_risk_signals")
    graph.add_conditional_edges(
        "collect_risk_signals",
        _check_error,
        {
            "next": "normalize_scores",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "normalize_scores",
        _check_error,
        {
            "next": "aggregate_risks",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "aggregate_risks",
        _check_error,
        {
            "next": "calculate_posture",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "calculate_posture",
        _check_error,
        {
            "next": "prioritize_actions",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("prioritize_actions", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
