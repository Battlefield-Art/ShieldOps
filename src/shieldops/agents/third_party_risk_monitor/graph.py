"""LangGraph workflow definition for the Third Party
Risk Monitor Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.third_party_risk_monitor.models import (
    ThirdPartyRiskMonitorState,
)
from shieldops.agents.third_party_risk_monitor.nodes import (
    assess_posture,
    evaluate_risk,
    generate_alerts,
    generate_report,
    inventory_vendors,
    monitor_changes,
)
from shieldops.agents.tracing import traced_node

_AGENT = "third_party_risk_monitor"


def _should_alert(
    state: ThirdPartyRiskMonitorState,
) -> str:
    """Route after risk evaluation: generate alerts if
    high-risk vendors found, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.high_risk_vendors > 0:
        return "generate_alerts"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Third Party Risk Monitor LangGraph
    workflow.

    Workflow:
        inventory_vendors -> assess_posture
            -> monitor_changes -> evaluate_risk
            -> [high_risk? -> generate_alerts]
            -> generate_report -> END
    """
    graph = StateGraph(ThirdPartyRiskMonitorState)

    graph.add_node(
        "inventory_vendors",
        traced_node(f"{_AGENT}.inventory_vendors", _AGENT)(inventory_vendors),
    )
    graph.add_node(
        "assess_posture",
        traced_node(f"{_AGENT}.assess_posture", _AGENT)(assess_posture),
    )
    graph.add_node(
        "monitor_changes",
        traced_node(f"{_AGENT}.monitor_changes", _AGENT)(monitor_changes),
    )
    graph.add_node(
        "evaluate_risk",
        traced_node(f"{_AGENT}.evaluate_risk", _AGENT)(evaluate_risk),
    )
    graph.add_node(
        "generate_alerts",
        traced_node(f"{_AGENT}.generate_alerts", _AGENT)(generate_alerts),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("inventory_vendors")
    graph.add_edge("inventory_vendors", "assess_posture")
    graph.add_edge("assess_posture", "monitor_changes")
    graph.add_edge("monitor_changes", "evaluate_risk")
    graph.add_conditional_edges(
        "evaluate_risk",
        _should_alert,
        {
            "generate_alerts": "generate_alerts",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_alerts", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_third_party_risk_monitor_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Third Party Risk Monitor
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
