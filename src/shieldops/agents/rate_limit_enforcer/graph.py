"""Rate Limit Enforcer Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.rate_limit_enforcer.models import (
    RateLimitEnforcerState,
)
from shieldops.agents.rate_limit_enforcer.nodes import (
    apply_limits,
    classify_patterns,
    detect_anomalies,
    monitor_traffic,
    notify_stakeholders,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "rate_limit_enforcer"


def _check_error(
    state: RateLimitEnforcerState,
) -> str:
    return "report" if state.error else "next"


def create_rate_limit_enforcer_graph() -> StateGraph:
    """Build the Rate Limit Enforcer workflow."""
    graph = StateGraph(RateLimitEnforcerState)

    graph.add_node(
        "monitor_traffic",
        traced_node("rle.monitor_traffic", _AGENT)(monitor_traffic),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node("rle.detect_anomalies", _AGENT)(detect_anomalies),
    )
    graph.add_node(
        "classify_patterns",
        traced_node("rle.classify_patterns", _AGENT)(classify_patterns),
    )
    graph.add_node(
        "apply_limits",
        traced_node("rle.apply_limits", _AGENT)(apply_limits),
    )
    graph.add_node(
        "notify_stakeholders",
        traced_node("rle.notify_stakeholders", _AGENT)(notify_stakeholders),
    )
    graph.add_node(
        "report",
        traced_node("rle.report", _AGENT)(report),
    )

    graph.set_entry_point("monitor_traffic")

    graph.add_conditional_edges(
        "monitor_traffic",
        _check_error,
        {
            "report": "report",
            "next": "detect_anomalies",
        },
    )
    graph.add_conditional_edges(
        "detect_anomalies",
        _check_error,
        {
            "report": "report",
            "next": "classify_patterns",
        },
    )
    graph.add_conditional_edges(
        "classify_patterns",
        _check_error,
        {"report": "report", "next": "apply_limits"},
    )
    graph.add_conditional_edges(
        "apply_limits",
        _check_error,
        {
            "report": "report",
            "next": "notify_stakeholders",
        },
    )
    graph.add_edge("notify_stakeholders", "report")
    graph.add_edge("report", END)

    return graph
