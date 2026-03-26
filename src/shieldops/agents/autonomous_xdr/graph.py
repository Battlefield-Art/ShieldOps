"""LangGraph workflow definition for the Autonomous XDR Agent.

Pipeline: collect_telemetry -> normalize_signals ->
correlate_cross_domain -> detect_campaigns ->
auto_investigate -> respond -> report.
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.autonomous_xdr.models import (
    AutonomousXDRState,
)
from shieldops.agents.autonomous_xdr.nodes import (
    auto_investigate,
    collect_telemetry,
    correlate_cross_domain,
    detect_campaigns,
    normalize_signals,
    report,
    respond,
)
from shieldops.agents.tracing import traced_node

_AGENT = "autonomous_xdr"


def _should_continue(
    state: AutonomousXDRState,
) -> str:
    """Route after telemetry collection."""
    if state.error:
        return "report"
    if not state.signals_collected:
        return "report"
    return "normalize_signals"


def _should_investigate(
    state: AutonomousXDRState,
) -> str:
    """Route after campaign detection."""
    if state.campaigns_detected:
        return "auto_investigate"
    return "report"


def build_graph() -> StateGraph:
    """Build the Autonomous XDR LangGraph workflow."""
    graph = StateGraph(AutonomousXDRState)

    # Add all nodes with tracing
    graph.add_node(
        "collect_telemetry",
        traced_node(
            "autonomous_xdr.collect_telemetry",
            _AGENT,
        )(collect_telemetry),
    )
    graph.add_node(
        "normalize_signals",
        traced_node(
            "autonomous_xdr.normalize_signals",
            _AGENT,
        )(normalize_signals),
    )
    graph.add_node(
        "correlate_cross_domain",
        traced_node(
            "autonomous_xdr.correlate_cross_domain",
            _AGENT,
        )(correlate_cross_domain),
    )
    graph.add_node(
        "detect_campaigns",
        traced_node(
            "autonomous_xdr.detect_campaigns",
            _AGENT,
        )(detect_campaigns),
    )
    graph.add_node(
        "auto_investigate",
        traced_node(
            "autonomous_xdr.auto_investigate",
            _AGENT,
        )(auto_investigate),
    )
    graph.add_node(
        "respond",
        traced_node(
            "autonomous_xdr.respond",
            _AGENT,
        )(respond),
    )
    graph.add_node(
        "report",
        traced_node(
            "autonomous_xdr.report",
            _AGENT,
        )(report),
    )

    # Entry point
    graph.set_entry_point("collect_telemetry")

    # Edges
    graph.add_conditional_edges(
        "collect_telemetry",
        _should_continue,
        {
            "normalize_signals": "normalize_signals",
            "report": "report",
        },
    )
    graph.add_edge(
        "normalize_signals",
        "correlate_cross_domain",
    )
    graph.add_edge(
        "correlate_cross_domain",
        "detect_campaigns",
    )
    graph.add_conditional_edges(
        "detect_campaigns",
        _should_investigate,
        {
            "auto_investigate": "auto_investigate",
            "report": "report",
        },
    )
    graph.add_edge("auto_investigate", "respond")
    graph.add_edge("respond", "report")
    graph.add_edge("report", END)

    return graph


def create_autonomous_xdr_graph() -> StateGraph:
    """Factory function for the Autonomous XDR graph."""
    return build_graph()
