"""Performance Profiler Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import PerformanceProfilerState
from .nodes import (
    analyze_latency,
    collect_traces,
    detect_bottlenecks,
    generate_report,
    identify_contention,
    recommend,
)
from .tools import PerformanceProfilerToolkit


def _should_recommend(state: Any) -> str:
    """Route after detect_bottlenecks: recommend if bottlenecks found, else report."""
    if isinstance(state, dict):
        bottlenecks = state.get("bottlenecks", [])
    else:
        bottlenecks = getattr(state, "bottlenecks", [])

    if bottlenecks:
        return "recommend"
    return "generate_report"


def build_graph(
    toolkit: PerformanceProfilerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Performance Profiler agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect_traces(state: Any) -> dict[str, Any]:
        return await collect_traces(_to_dict(state), toolkit)

    async def _analyze_latency(state: Any) -> dict[str, Any]:
        return await analyze_latency(_to_dict(state), toolkit)

    async def _detect_bottlenecks(state: Any) -> dict[str, Any]:
        return await detect_bottlenecks(_to_dict(state), toolkit)

    async def _identify_contention(state: Any) -> dict[str, Any]:
        return await identify_contention(_to_dict(state), toolkit)

    async def _recommend(state: Any) -> dict[str, Any]:
        return await recommend(_to_dict(state), toolkit)

    async def _generate_report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(PerformanceProfilerState)
    graph.add_node("collect_traces", _collect_traces)
    graph.add_node("analyze_latency", _analyze_latency)
    graph.add_node("detect_bottlenecks", _detect_bottlenecks)
    graph.add_node("identify_contention", _identify_contention)
    graph.add_node("recommend", _recommend)
    graph.add_node("generate_report", _generate_report)

    graph.set_entry_point("collect_traces")
    graph.add_edge("collect_traces", "analyze_latency")
    graph.add_edge("analyze_latency", "detect_bottlenecks")

    # Conditional: if bottlenecks found → recommend → report; else → report
    graph.add_conditional_edges(
        "detect_bottlenecks",
        _should_recommend,
        {"recommend": "identify_contention", "generate_report": "generate_report"},
    )
    graph.add_edge("identify_contention", "recommend")
    graph.add_edge("recommend", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_performance_profiler_graph(
    apm_client: Any | None = None,
    metrics_store: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Performance Profiler agent graph with dependencies."""
    toolkit = PerformanceProfilerToolkit(
        apm_client=apm_client,
        metrics_store=metrics_store,
    )
    return build_graph(toolkit)
