"""LangGraph workflow definition for the Runtime
Application Protector Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.runtime_application_protector.models import (
    RuntimeApplicationProtectorState,
)
from shieldops.agents.runtime_application_protector.nodes import (
    classify_threat,
    detect_attacks,
    generate_report,
    instrument_app,
    monitor_runtime,
    protect,
)
from shieldops.agents.tracing import traced_node

_AGENT = "runtime_application_protector"


def _should_protect(
    state: RuntimeApplicationProtectorState,
) -> str:
    """Route after classification: protect if attacks
    found or on error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.attacks_detected > 0:
        return "protect"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Runtime Application Protector LangGraph
    workflow.

    Workflow:
        instrument_app -> monitor_runtime
            -> detect_attacks -> classify_threat
            -> [attacks? -> protect]
            -> generate_report -> END
    """
    graph = StateGraph(RuntimeApplicationProtectorState)

    graph.add_node(
        "instrument_app",
        traced_node(f"{_AGENT}.instrument_app", _AGENT)(instrument_app),
    )
    graph.add_node(
        "monitor_runtime",
        traced_node(f"{_AGENT}.monitor_runtime", _AGENT)(monitor_runtime),
    )
    graph.add_node(
        "detect_attacks",
        traced_node(f"{_AGENT}.detect_attacks", _AGENT)(detect_attacks),
    )
    graph.add_node(
        "classify_threat",
        traced_node(f"{_AGENT}.classify_threat", _AGENT)(classify_threat),
    )
    graph.add_node(
        "protect",
        traced_node(f"{_AGENT}.protect", _AGENT)(protect),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("instrument_app")
    graph.add_edge("instrument_app", "monitor_runtime")
    graph.add_edge("monitor_runtime", "detect_attacks")
    graph.add_edge("detect_attacks", "classify_threat")
    graph.add_conditional_edges(
        "classify_threat",
        _should_protect,
        {
            "protect": "protect",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("protect", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_runtime_application_protector_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Runtime Application Protector
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
