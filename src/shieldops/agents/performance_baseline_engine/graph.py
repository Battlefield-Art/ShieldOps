"""Performance Baseline Engine Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.performance_baseline_engine.models import (
    PerformanceBaselineEngineState,
)
from shieldops.agents.performance_baseline_engine.nodes import (
    alert_deviations,
    analyze_trends,
    collect_metrics,
    detect_regressions,
    establish_baselines,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "performance_baseline_engine"


def _check_error(
    state: PerformanceBaselineEngineState,
) -> str:
    return "report" if state.error else "next"


def create_performance_baseline_engine_graph() -> StateGraph:
    """Build the Performance Baseline Engine workflow."""
    graph = StateGraph(PerformanceBaselineEngineState)

    graph.add_node(
        "collect_metrics",
        traced_node("pbe.collect_metrics", _AGENT)(collect_metrics),
    )
    graph.add_node(
        "establish_baselines",
        traced_node("pbe.establish_baselines", _AGENT)(establish_baselines),
    )
    graph.add_node(
        "detect_regressions",
        traced_node("pbe.detect_regressions", _AGENT)(detect_regressions),
    )
    graph.add_node(
        "analyze_trends",
        traced_node("pbe.analyze_trends", _AGENT)(analyze_trends),
    )
    graph.add_node(
        "alert_deviations",
        traced_node("pbe.alert_deviations", _AGENT)(alert_deviations),
    )
    graph.add_node(
        "report",
        traced_node("pbe.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_metrics")

    graph.add_conditional_edges(
        "collect_metrics",
        _check_error,
        {"report": "report", "next": "establish_baselines"},
    )
    graph.add_conditional_edges(
        "establish_baselines",
        _check_error,
        {"report": "report", "next": "detect_regressions"},
    )
    graph.add_conditional_edges(
        "detect_regressions",
        _check_error,
        {"report": "report", "next": "analyze_trends"},
    )
    graph.add_conditional_edges(
        "analyze_trends",
        _check_error,
        {"report": "report", "next": "alert_deviations"},
    )
    graph.add_edge("alert_deviations", "report")
    graph.add_edge("report", END)

    return graph
