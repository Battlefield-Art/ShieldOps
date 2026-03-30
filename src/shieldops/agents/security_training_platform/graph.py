"""LangGraph workflow for the Security Training Platform Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_training_platform.models import (
    SecurityTrainingPlatformState,
)
from shieldops.agents.security_training_platform.nodes import (
    assess_baseline,
    create_campaign,
    deploy_simulation,
    generate_report,
    score_risk,
    track_results,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_training_platform"


def _should_create_campaign(
    state: SecurityTrainingPlatformState,
) -> str:
    """Route after baseline assessment."""
    if state.error:
        return "generate_report"
    if state.baseline_assessments:
        return "create_campaign"
    return "generate_report"


def _should_score(
    state: SecurityTrainingPlatformState,
) -> str:
    """Route after tracking based on results."""
    if state.completion_rate > 0:
        return "score_risk"
    return "generate_report"


def create_security_training_platform_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Training Platform LangGraph.

    Workflow:
        assess_baseline
          -> [has_assessments?] -> create_campaign
          -> deploy_simulation
          -> track_results
          -> [has_completion?] -> score_risk
          -> generate_report
    """
    graph = StateGraph(SecurityTrainingPlatformState)

    graph.add_node(
        "assess_baseline",
        traced_node(
            f"{_AGENT}.assess_baseline",
            _AGENT,
        )(assess_baseline),
    )
    graph.add_node(
        "create_campaign",
        traced_node(
            f"{_AGENT}.create_campaign",
            _AGENT,
        )(create_campaign),
    )
    graph.add_node(
        "deploy_simulation",
        traced_node(
            f"{_AGENT}.deploy_simulation",
            _AGENT,
        )(deploy_simulation),
    )
    graph.add_node(
        "track_results",
        traced_node(
            f"{_AGENT}.track_results",
            _AGENT,
        )(track_results),
    )
    graph.add_node(
        "score_risk",
        traced_node(
            f"{_AGENT}.score_risk",
            _AGENT,
        )(score_risk),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("assess_baseline")
    graph.add_conditional_edges(
        "assess_baseline",
        _should_create_campaign,
        {
            "create_campaign": "create_campaign",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("create_campaign", "deploy_simulation")
    graph.add_edge("deploy_simulation", "track_results")
    graph.add_conditional_edges(
        "track_results",
        _should_score,
        {
            "score_risk": "score_risk",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("score_risk", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
