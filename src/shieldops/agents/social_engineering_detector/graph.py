"""Social Engineering Detector Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.social_engineering_detector.models import SocialEngineeringDetectorState
from shieldops.agents.social_engineering_detector.nodes import (
    analyze_patterns,
    assess_risk,
    classify_attack,
    collect_signals,
    recommend,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "social_engineering_detector"


def _check_error(state: SocialEngineeringDetectorState) -> str:
    return "report" if state.error else "next"


def create_social_engineering_detector_graph() -> StateGraph:
    """Build the Social Engineering Detector LangGraph workflow."""
    graph = StateGraph(SocialEngineeringDetectorState)

    graph.add_node(
        "collect_signals",
        traced_node(f"{_AGENT}.collect_signals", _AGENT)(collect_signals),
    )
    graph.add_node(
        "analyze_patterns",
        traced_node(f"{_AGENT}.analyze_patterns", _AGENT)(analyze_patterns),
    )
    graph.add_node(
        "classify_attack",
        traced_node(f"{_AGENT}.classify_attack", _AGENT)(classify_attack),
    )
    graph.add_node(
        "assess_risk",
        traced_node(f"{_AGENT}.assess_risk", _AGENT)(assess_risk),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_signals")

    graph.add_conditional_edges(
        "collect_signals",
        _check_error,
        {"next": "analyze_patterns", "report": "report"},
    )
    graph.add_conditional_edges(
        "analyze_patterns",
        _check_error,
        {"next": "classify_attack", "report": "report"},
    )
    graph.add_conditional_edges(
        "classify_attack",
        _check_error,
        {"next": "assess_risk", "report": "report"},
    )
    graph.add_conditional_edges(
        "assess_risk",
        _check_error,
        {"next": "recommend", "report": "report"},
    )
    graph.add_edge("recommend", "report")
    graph.add_edge("report", END)

    return graph
