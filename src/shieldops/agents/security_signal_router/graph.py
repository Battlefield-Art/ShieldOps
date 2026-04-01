"""LangGraph workflow for the Security Signal Router Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_signal_router.models import (
    SecuritySignalRouterState,
)
from shieldops.agents.security_signal_router.nodes import (
    classify_signals,
    dispatch_signals,
    evaluate_routing,
    generate_report,
    ingest_signals,
    track_outcomes,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_signal_router"


def _should_dispatch(
    state: SecuritySignalRouterState,
) -> str:
    """Route after routing evaluation."""
    if state.error:
        return "generate_report"
    if state.routing_decisions:
        return "dispatch_signals"
    return "generate_report"


def _should_track(
    state: SecuritySignalRouterState,
) -> str:
    """Route after dispatch."""
    if state.dispatch_results:
        return "track_outcomes"
    return "generate_report"


def create_security_signal_router_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Signal Router LangGraph.

    Workflow:
        ingest_signals -> classify_signals -> evaluate_routing
          -> [has_decisions?] -> dispatch_signals
          -> [has_dispatches?] -> track_outcomes -> generate_report
    """
    graph = StateGraph(SecuritySignalRouterState)

    graph.add_node(
        "ingest_signals",
        traced_node(f"{_AGENT}.ingest_signals", _AGENT)(
            ingest_signals,
        ),
    )
    graph.add_node(
        "classify_signals",
        traced_node(f"{_AGENT}.classify_signals", _AGENT)(
            classify_signals,
        ),
    )
    graph.add_node(
        "evaluate_routing",
        traced_node(f"{_AGENT}.evaluate_routing", _AGENT)(
            evaluate_routing,
        ),
    )
    graph.add_node(
        "dispatch_signals",
        traced_node(f"{_AGENT}.dispatch_signals", _AGENT)(
            dispatch_signals,
        ),
    )
    graph.add_node(
        "track_outcomes",
        traced_node(f"{_AGENT}.track_outcomes", _AGENT)(
            track_outcomes,
        ),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(
            generate_report,
        ),
    )

    graph.set_entry_point("ingest_signals")
    graph.add_edge("ingest_signals", "classify_signals")
    graph.add_edge("classify_signals", "evaluate_routing")
    graph.add_conditional_edges(
        "evaluate_routing",
        _should_dispatch,
        {
            "dispatch_signals": "dispatch_signals",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "dispatch_signals",
        _should_track,
        {
            "track_outcomes": "track_outcomes",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("track_outcomes", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
