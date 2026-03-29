"""Threat Brief Generator Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.threat_brief_generator.models import ThreatBriefGeneratorState
from shieldops.agents.threat_brief_generator.nodes import (
    analyze_threats,
    assess_relevance,
    collect_intel,
    draft_brief,
    report,
    review,
)
from shieldops.agents.tracing import traced_node

_AGENT = "threat_brief_generator"


def _check_error(state: ThreatBriefGeneratorState) -> str:
    return "report" if state.error else "next"


def create_threat_brief_generator_graph() -> StateGraph:
    """Build the Threat Brief Generator workflow."""
    graph = StateGraph(ThreatBriefGeneratorState)

    graph.add_node(
        "collect_intel",
        traced_node(f"{_AGENT}.collect_intel", _AGENT)(collect_intel),
    )
    graph.add_node(
        "analyze_threats",
        traced_node(f"{_AGENT}.analyze_threats", _AGENT)(analyze_threats),
    )
    graph.add_node(
        "assess_relevance",
        traced_node(f"{_AGENT}.assess_relevance", _AGENT)(assess_relevance),
    )
    graph.add_node(
        "draft_brief",
        traced_node(f"{_AGENT}.draft_brief", _AGENT)(draft_brief),
    )
    graph.add_node(
        "review",
        traced_node(f"{_AGENT}.review", _AGENT)(review),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_intel")

    graph.add_conditional_edges(
        "collect_intel",
        _check_error,
        {"next": "analyze_threats", "report": "report"},
    )
    graph.add_conditional_edges(
        "analyze_threats",
        _check_error,
        {"next": "assess_relevance", "report": "report"},
    )
    graph.add_conditional_edges(
        "assess_relevance",
        _check_error,
        {"next": "draft_brief", "report": "report"},
    )
    graph.add_conditional_edges(
        "draft_brief",
        _check_error,
        {"next": "review", "report": "report"},
    )
    graph.add_edge("review", "report")
    graph.add_edge("report", END)

    return graph
