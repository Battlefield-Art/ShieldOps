"""LangGraph workflow definition for the Insider Risk
Scorer Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.insider_risk_scorer.models import (
    InsiderRiskScorerState,
)
from shieldops.agents.insider_risk_scorer.nodes import (
    analyze_behavior,
    collect_signals,
    detect_anomalies,
    generate_alerts,
    generate_report,
    score_risk,
)
from shieldops.agents.tracing import traced_node

_AGENT = "insider_risk_scorer"


def _should_alert(
    state: InsiderRiskScorerState,
) -> str:
    """Route after anomaly detection: alert if high-risk
    users exist, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.high_risk_users:
        return "generate_alerts"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Insider Risk Scorer LangGraph workflow.

    Workflow:
        collect_signals -> analyze_behavior
            -> score_risk -> detect_anomalies
            -> [high_risk? -> generate_alerts]
            -> generate_report -> END
    """
    graph = StateGraph(InsiderRiskScorerState)

    graph.add_node(
        "collect_signals",
        traced_node(f"{_AGENT}.collect_signals", _AGENT)(collect_signals),
    )
    graph.add_node(
        "analyze_behavior",
        traced_node(f"{_AGENT}.analyze_behavior", _AGENT)(analyze_behavior),
    )
    graph.add_node(
        "score_risk",
        traced_node(f"{_AGENT}.score_risk", _AGENT)(score_risk),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(f"{_AGENT}.detect_anomalies", _AGENT)(detect_anomalies),
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
    graph.set_entry_point("collect_signals")
    graph.add_edge("collect_signals", "analyze_behavior")
    graph.add_edge("analyze_behavior", "score_risk")
    graph.add_edge("score_risk", "detect_anomalies")
    graph.add_conditional_edges(
        "detect_anomalies",
        _should_alert,
        {
            "generate_alerts": "generate_alerts",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_alerts", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_insider_risk_scorer_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create an Insider Risk Scorer graph
    with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
