"""LangGraph workflow for the Governance Dashboard Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.governance_dashboard.models import (
    GovernanceDashboardState,
)
from shieldops.agents.governance_dashboard.nodes import (
    assess_policies,
    collect_metrics,
    executive_summary,
    generate_insights,
    report,
    score_risk,
)
from shieldops.agents.tracing import traced_node

_AGENT = "governance_dashboard"


def _check_error(
    state: GovernanceDashboardState,
) -> str:
    """Route to report on error."""
    if state.error:
        return "report"
    return "continue"


def create_governance_dashboard_graph() -> StateGraph:
    """Build the Governance Dashboard workflow.

    Workflow:
        collect_metrics
            -> [error? -> report -> END]
            -> assess_policies
            -> [error? -> report -> END]
            -> score_risk
            -> [error? -> report -> END]
            -> generate_insights
            -> [error? -> report -> END]
            -> executive_summary
            -> report -> END
    """
    graph = StateGraph(GovernanceDashboardState)

    graph.add_node(
        "collect_metrics",
        traced_node(
            "governance_dashboard.collect_metrics",
            _AGENT,
        )(collect_metrics),
    )
    graph.add_node(
        "assess_policies",
        traced_node(
            "governance_dashboard.assess_policies",
            _AGENT,
        )(assess_policies),
    )
    graph.add_node(
        "score_risk",
        traced_node(
            "governance_dashboard.score_risk",
            _AGENT,
        )(score_risk),
    )
    graph.add_node(
        "generate_insights",
        traced_node(
            "governance_dashboard.generate_insights",
            _AGENT,
        )(generate_insights),
    )
    graph.add_node(
        "executive_summary",
        traced_node(
            "governance_dashboard.executive_summary",
            _AGENT,
        )(executive_summary),
    )
    graph.add_node(
        "report",
        traced_node(
            "governance_dashboard.report",
            _AGENT,
        )(report),
    )

    graph.set_entry_point("collect_metrics")

    graph.add_conditional_edges(
        "collect_metrics",
        _check_error,
        {
            "report": "report",
            "continue": "assess_policies",
        },
    )
    graph.add_conditional_edges(
        "assess_policies",
        _check_error,
        {
            "report": "report",
            "continue": "score_risk",
        },
    )
    graph.add_conditional_edges(
        "score_risk",
        _check_error,
        {
            "report": "report",
            "continue": "generate_insights",
        },
    )
    graph.add_conditional_edges(
        "generate_insights",
        _check_error,
        {
            "report": "report",
            "continue": "executive_summary",
        },
    )
    graph.add_edge("executive_summary", "report")
    graph.add_edge("report", END)

    return graph
