"""LangGraph workflow definition for the SOC Metrics Analyzer."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.soc_metrics_analyzer.models import (
    SOCMetricsAnalyzerState,
)
from shieldops.agents.soc_metrics_analyzer.nodes import (
    analyze_performance,
    benchmark_industry,
    collect_metrics,
    detect_bottlenecks,
    generate_report,
    recommend_improvements,
)
from shieldops.agents.tracing import traced_node

_AGENT = "soc_metrics_analyzer"


def _has_bottlenecks(
    state: SOCMetricsAnalyzerState,
) -> str:
    """Route based on whether bottlenecks were found."""
    if state.bottlenecks:
        return "benchmark_industry"
    return "generate_report"


def build_graph(
    toolkit: object | None = None,
) -> StateGraph:
    """Build the SOC Metrics Analyzer LangGraph workflow.

    Workflow:
        collect_metrics -> analyze_performance
            -> detect_bottlenecks
                -> [bottlenecks?]
                    yes -> benchmark_industry
                        -> recommend_improvements
                        -> generate_report -> END
                    no  -> generate_report -> END
    """
    graph = StateGraph(SOCMetricsAnalyzerState)

    graph.add_node(
        "collect_metrics",
        traced_node(
            f"{_AGENT}.collect_metrics",
            _AGENT,
        )(collect_metrics),
    )
    graph.add_node(
        "analyze_performance",
        traced_node(
            f"{_AGENT}.analyze_performance",
            _AGENT,
        )(analyze_performance),
    )
    graph.add_node(
        "detect_bottlenecks",
        traced_node(
            f"{_AGENT}.detect_bottlenecks",
            _AGENT,
        )(detect_bottlenecks),
    )
    graph.add_node(
        "benchmark_industry",
        traced_node(
            f"{_AGENT}.benchmark_industry",
            _AGENT,
        )(benchmark_industry),
    )
    graph.add_node(
        "recommend_improvements",
        traced_node(
            f"{_AGENT}.recommend_improvements",
            _AGENT,
        )(recommend_improvements),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    graph.set_entry_point("collect_metrics")
    graph.add_edge(
        "collect_metrics",
        "analyze_performance",
    )
    graph.add_edge(
        "analyze_performance",
        "detect_bottlenecks",
    )
    graph.add_conditional_edges(
        "detect_bottlenecks",
        _has_bottlenecks,
        {
            "benchmark_industry": "benchmark_industry",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge(
        "benchmark_industry",
        "recommend_improvements",
    )
    graph.add_edge(
        "recommend_improvements",
        "generate_report",
    )
    graph.add_edge("generate_report", END)

    return graph


def create_soc_metrics_analyzer_graph(
    **clients: object,
) -> StateGraph:
    """Factory — create the graph with optional clients."""
    from shieldops.agents.soc_metrics_analyzer.nodes import (
        set_toolkit,
    )
    from shieldops.agents.soc_metrics_analyzer.tools import (
        SOCMetricsAnalyzerToolkit,
    )

    toolkit = SOCMetricsAnalyzerToolkit(
        siem_client=clients.get("siem_client"),
        soar_client=clients.get("soar_client"),
        ticketing_client=clients.get("ticketing_client"),
        metrics_store=clients.get("metrics_store"),
        repository=clients.get("repository"),
    )
    set_toolkit(toolkit)
    return build_graph(toolkit)
