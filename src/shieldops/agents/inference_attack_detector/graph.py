"""Inference Attack Detector Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.inference_attack_detector.models import InferenceAttackDetectorState
from shieldops.agents.inference_attack_detector.nodes import (
    analyze_patterns,
    assess_impact,
    classify_attack,
    collect_queries,
    mitigate,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "inference_attack_detector"


def _check_error(state: InferenceAttackDetectorState) -> str:
    return "report" if state.error else "next"


def create_inference_attack_detector_graph() -> StateGraph:
    """Build the Inference Attack Detector LangGraph workflow."""
    graph = StateGraph(InferenceAttackDetectorState)

    graph.add_node(
        "collect_queries",
        traced_node(f"{_AGENT}.collect_queries", _AGENT)(collect_queries),
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
        "assess_impact",
        traced_node(f"{_AGENT}.assess_impact", _AGENT)(assess_impact),
    )
    graph.add_node(
        "mitigate",
        traced_node(f"{_AGENT}.mitigate", _AGENT)(mitigate),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_queries")

    graph.add_conditional_edges(
        "collect_queries",
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
        {"next": "assess_impact", "report": "report"},
    )
    graph.add_conditional_edges(
        "assess_impact",
        _check_error,
        {"next": "mitigate", "report": "report"},
    )
    graph.add_edge("mitigate", "report")
    graph.add_edge("report", END)

    return graph
