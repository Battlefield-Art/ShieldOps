"""LangGraph workflow definition for the Security
Metric Dashboard Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_metric_dashboard.models import (
    SecurityMetricDashboardState,
)
from shieldops.agents.security_metric_dashboard.nodes import (
    benchmark_industry,
    build_dashboard,
    calculate_kpis,
    collect_metrics,
    generate_report,
    normalize_metrics,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_metric_dashboard"


def _should_benchmark(
    state: SecurityMetricDashboardState,
) -> str:
    """Route after KPI calculation: benchmark if KPIs
    exist, otherwise skip to dashboard."""
    if state.error:
        return "generate_report"
    if state.kpi_count > 0:
        return "benchmark_industry"
    return "build_dashboard"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Metric Dashboard LangGraph
    workflow.

    Workflow:
        collect_metrics -> normalize_metrics
            -> calculate_kpis
            -> [kpis? -> benchmark_industry]
            -> build_dashboard -> generate_report -> END
    """
    graph = StateGraph(SecurityMetricDashboardState)

    graph.add_node(
        "collect_metrics",
        traced_node(f"{_AGENT}.collect_metrics", _AGENT)(collect_metrics),
    )
    graph.add_node(
        "normalize_metrics",
        traced_node(f"{_AGENT}.normalize_metrics", _AGENT)(normalize_metrics),
    )
    graph.add_node(
        "calculate_kpis",
        traced_node(f"{_AGENT}.calculate_kpis", _AGENT)(calculate_kpis),
    )
    graph.add_node(
        "benchmark_industry",
        traced_node(f"{_AGENT}.benchmark_industry", _AGENT)(benchmark_industry),
    )
    graph.add_node(
        "build_dashboard",
        traced_node(f"{_AGENT}.build_dashboard", _AGENT)(build_dashboard),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("collect_metrics")
    graph.add_edge("collect_metrics", "normalize_metrics")
    graph.add_edge("normalize_metrics", "calculate_kpis")
    graph.add_conditional_edges(
        "calculate_kpis",
        _should_benchmark,
        {
            "benchmark_industry": "benchmark_industry",
            "build_dashboard": "build_dashboard",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("benchmark_industry", "build_dashboard")
    graph.add_edge("build_dashboard", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_metric_dashboard_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Metric Dashboard
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
