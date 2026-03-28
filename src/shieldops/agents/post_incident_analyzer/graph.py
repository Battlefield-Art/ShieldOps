"""LangGraph workflow definition for the Post-Incident Analyzer Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.post_incident_analyzer.models import (
    PostIncidentAnalyzerState,
)
from shieldops.agents.post_incident_analyzer.nodes import (
    action_items,
    gather_timeline,
    impact_assessment,
    lessons_learned,
    report,
    root_cause_analysis,
)
from shieldops.agents.tracing import traced_node

_AGENT = "post_incident_analyzer"


def _route_or_report(
    state: PostIncidentAnalyzerState,
) -> str:
    """If an error has been recorded, skip straight to report."""
    if state.error:
        return "report"
    return "next"


def create_post_incident_analyzer_graph() -> StateGraph:
    """Build the Post-Incident Analyzer LangGraph workflow.

    Flow:
        gather_timeline -> root_cause_analysis -> impact_assessment
        -> lessons_learned -> action_items -> report -> END

    Any node that sets ``state.error`` causes a conditional edge
    to jump directly to the *report* node so partial results are
    still captured.
    """
    graph = StateGraph(PostIncidentAnalyzerState)

    # -- nodes -------------------------------------------------------
    graph.add_node(
        "gather_timeline",
        traced_node("post_incident_analyzer.gather_timeline", _AGENT)(gather_timeline),
    )
    graph.add_node(
        "root_cause_analysis",
        traced_node("post_incident_analyzer.root_cause_analysis", _AGENT)(root_cause_analysis),
    )
    graph.add_node(
        "impact_assessment",
        traced_node("post_incident_analyzer.impact_assessment", _AGENT)(impact_assessment),
    )
    graph.add_node(
        "lessons_learned",
        traced_node("post_incident_analyzer.lessons_learned", _AGENT)(lessons_learned),
    )
    graph.add_node(
        "action_items",
        traced_node("post_incident_analyzer.action_items", _AGENT)(action_items),
    )
    graph.add_node(
        "report",
        traced_node("post_incident_analyzer.report", _AGENT)(report),
    )

    # -- edges -------------------------------------------------------
    graph.set_entry_point("gather_timeline")

    graph.add_conditional_edges(
        "gather_timeline",
        _route_or_report,
        {"next": "root_cause_analysis", "report": "report"},
    )
    graph.add_conditional_edges(
        "root_cause_analysis",
        _route_or_report,
        {"next": "impact_assessment", "report": "report"},
    )
    graph.add_conditional_edges(
        "impact_assessment",
        _route_or_report,
        {"next": "lessons_learned", "report": "report"},
    )
    graph.add_conditional_edges(
        "lessons_learned",
        _route_or_report,
        {"next": "action_items", "report": "report"},
    )
    graph.add_conditional_edges(
        "action_items",
        _route_or_report,
        {"next": "report", "report": "report"},
    )
    graph.add_edge("report", END)

    return graph
