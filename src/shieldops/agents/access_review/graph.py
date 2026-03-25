"""LangGraph workflow definition for the Access Review Agent."""

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.access_review.models import AccessReviewState
from shieldops.agents.access_review.nodes import (
    analyze_access,
    certify,
    collect_entitlements,
    generate_tasks,
    identify_violations,
    report,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def has_violations(state: AccessReviewState) -> str:
    """Route based on whether violations were found."""
    if state.error:
        return "report"
    if state.violations:
        return "identify_violations"
    return "report"


def has_tasks(state: AccessReviewState) -> str:
    """Route based on whether review tasks were generated."""
    if state.error:
        return "report"
    if state.review_tasks:
        return "certify"
    return "report"


def create_access_review_graph() -> StateGraph[AccessReviewState]:
    """Build the Access Review Agent LangGraph workflow.

    Workflow:
        collect_entitlements -> analyze_access
            -> [conditional: identify_violations OR report]
            -> generate_tasks
            -> [conditional: certify OR report]
            -> report -> END
    """
    graph = StateGraph(AccessReviewState)

    _agent = "access_review"
    graph.add_node(
        "collect_entitlements",
        traced_node("access_review.collect_entitlements", _agent)(collect_entitlements),
    )
    graph.add_node(
        "analyze_access",
        traced_node("access_review.analyze_access", _agent)(analyze_access),
    )
    graph.add_node(
        "identify_violations",
        traced_node("access_review.identify_violations", _agent)(identify_violations),
    )
    graph.add_node(
        "generate_tasks",
        traced_node("access_review.generate_tasks", _agent)(generate_tasks),
    )
    graph.add_node(
        "certify",
        traced_node("access_review.certify", _agent)(certify),
    )
    graph.add_node(
        "report",
        traced_node("access_review.report", _agent)(report),
    )

    # Define edges
    graph.set_entry_point("collect_entitlements")
    graph.add_edge("collect_entitlements", "analyze_access")
    graph.add_conditional_edges(
        "analyze_access",
        has_violations,
        {
            "identify_violations": "identify_violations",
            "report": "report",
        },
    )
    graph.add_edge("identify_violations", "generate_tasks")
    graph.add_conditional_edges(
        "generate_tasks",
        has_tasks,
        {
            "certify": "certify",
            "report": "report",
        },
    )
    graph.add_edge("certify", "report")
    graph.add_edge("report", END)

    return graph
