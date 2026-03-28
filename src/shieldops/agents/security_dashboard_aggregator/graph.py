"""LangGraph workflow for the Dashboard Aggregator Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_dashboard_aggregator.models import (
    SecurityDashboardAggregatorState,
)
from shieldops.agents.security_dashboard_aggregator.nodes import (
    aggregate_by_domain,
    calculate_kpis,
    collect_agent_metrics,
    detect_anomalies,
    generate_dashboard,
    generate_report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_dashboard_aggregator"


def _has_metrics(
    state: SecurityDashboardAggregatorState,
) -> str:
    """Route based on whether metrics exist."""
    if state.error:
        return END
    if not state.agent_metrics:
        return "generate_report"
    return "aggregate_by_domain"


def build_graph(
    toolkit: object | None = None,
) -> StateGraph:
    """Build the Dashboard Aggregator StateGraph.

    Workflow:
        collect_agent_metrics
        -> [no metrics? -> generate_report -> END]
        -> aggregate_by_domain -> calculate_kpis
        -> detect_anomalies -> generate_dashboard
        -> generate_report -> END
    """
    graph = StateGraph(SecurityDashboardAggregatorState)

    graph.add_node(
        "collect_agent_metrics",
        traced_node(
            f"{_AGENT}.collect_agent_metrics",
            _AGENT,
        )(collect_agent_metrics),
    )
    graph.add_node(
        "aggregate_by_domain",
        traced_node(f"{_AGENT}.aggregate_by_domain", _AGENT)(aggregate_by_domain),
    )
    graph.add_node(
        "calculate_kpis",
        traced_node(f"{_AGENT}.calculate_kpis", _AGENT)(calculate_kpis),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(f"{_AGENT}.detect_anomalies", _AGENT)(detect_anomalies),
    )
    graph.add_node(
        "generate_dashboard",
        traced_node(f"{_AGENT}.generate_dashboard", _AGENT)(generate_dashboard),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("collect_agent_metrics")
    graph.add_conditional_edges(
        "collect_agent_metrics",
        _has_metrics,
        {
            "aggregate_by_domain": ("aggregate_by_domain"),
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge("aggregate_by_domain", "calculate_kpis")
    graph.add_edge("calculate_kpis", "detect_anomalies")
    graph.add_edge("detect_anomalies", "generate_dashboard")
    graph.add_edge("generate_dashboard", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_dashboard_aggregator_graph(
    **clients: object,
) -> StateGraph:
    """Factory to create the Dashboard Aggregator graph."""
    return build_graph()
