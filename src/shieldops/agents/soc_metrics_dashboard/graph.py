"""SOC Metrics Dashboard Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.soc_metrics_dashboard.models import SocMetricsDashboardState
from shieldops.agents.soc_metrics_dashboard.nodes import (
    benchmark,
    collect_data,
    compute_kpis,
    identify_trends,
    recommend,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "soc_metrics_dashboard"


def _check_error(state: SocMetricsDashboardState) -> str:
    return "report" if state.error else "next"


def create_soc_metrics_dashboard_graph() -> StateGraph:
    """Build the SOC Metrics Dashboard workflow."""
    graph = StateGraph(SocMetricsDashboardState)

    graph.add_node(
        "collect_data",
        traced_node(f"{_AGENT}.collect_data", _AGENT)(collect_data),
    )
    graph.add_node(
        "compute_kpis",
        traced_node(f"{_AGENT}.compute_kpis", _AGENT)(compute_kpis),
    )
    graph.add_node(
        "identify_trends",
        traced_node(f"{_AGENT}.identify_trends", _AGENT)(identify_trends),
    )
    graph.add_node(
        "benchmark",
        traced_node(f"{_AGENT}.benchmark", _AGENT)(benchmark),
    )
    graph.add_node(
        "recommend",
        traced_node(f"{_AGENT}.recommend", _AGENT)(recommend),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_data")

    graph.add_conditional_edges(
        "collect_data",
        _check_error,
        {"next": "compute_kpis", "report": "report"},
    )
    graph.add_conditional_edges(
        "compute_kpis",
        _check_error,
        {"next": "identify_trends", "report": "report"},
    )
    graph.add_conditional_edges(
        "identify_trends",
        _check_error,
        {"next": "benchmark", "report": "report"},
    )
    graph.add_conditional_edges(
        "benchmark",
        _check_error,
        {"next": "recommend", "report": "report"},
    )
    graph.add_edge("recommend", "report")
    graph.add_edge("report", END)

    return graph
