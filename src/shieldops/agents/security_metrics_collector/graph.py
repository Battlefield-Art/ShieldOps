"""Security Metrics Collector Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_metrics_collector.models import SecurityMetricsCollectorState
from shieldops.agents.security_metrics_collector.nodes import (
    benchmark_performance,
    calculate_kpis,
    collect_data,
    define_metrics,
    generate_dashboard,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_metrics_collector"


def _check_error(state: SecurityMetricsCollectorState) -> str:
    return "report" if state.error else "next"


def create_security_metrics_collector_graph() -> StateGraph:
    """Build the Security Metrics Collector workflow."""
    graph = StateGraph(SecurityMetricsCollectorState)

    graph.add_node(
        "define_metrics",
        traced_node(f"{_AGENT}.define_metrics", _AGENT)(define_metrics),
    )
    graph.add_node(
        "collect_data",
        traced_node(f"{_AGENT}.collect_data", _AGENT)(collect_data),
    )
    graph.add_node(
        "calculate_kpis",
        traced_node(f"{_AGENT}.calculate_kpis", _AGENT)(calculate_kpis),
    )
    graph.add_node(
        "benchmark_performance",
        traced_node(f"{_AGENT}.benchmark_performance", _AGENT)(benchmark_performance),
    )
    graph.add_node(
        "generate_dashboard",
        traced_node(f"{_AGENT}.generate_dashboard", _AGENT)(generate_dashboard),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("define_metrics")

    graph.add_conditional_edges(
        "define_metrics",
        _check_error,
        {"next": "collect_data", "report": "report"},
    )
    graph.add_conditional_edges(
        "collect_data",
        _check_error,
        {"next": "calculate_kpis", "report": "report"},
    )
    graph.add_conditional_edges(
        "calculate_kpis",
        _check_error,
        {"next": "benchmark_performance", "report": "report"},
    )
    graph.add_conditional_edges(
        "benchmark_performance",
        _check_error,
        {"next": "generate_dashboard", "report": "report"},
    )
    graph.add_edge("generate_dashboard", "report")
    graph.add_edge("report", END)

    return graph
