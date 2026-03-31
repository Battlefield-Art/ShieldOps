"""Security Posture Scorer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecurityPostureScorerState
from .nodes import (
    benchmark,
    calculate_scores,
    collect_signals,
    generate_report,
    trend_analysis,
    weight_categories,
)
from .tools import SecurityPostureScorerToolkit


def build_graph(
    toolkit: SecurityPostureScorerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Posture Scorer graph.

    Flow:
        collect_signals -> weight_categories
        -> calculate_scores -> benchmark
        -> trend_analysis -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_signals(
            _to_dict(state),
            toolkit,
        )

    async def _weight(
        state: Any,
    ) -> dict[str, Any]:
        return await weight_categories(
            _to_dict(state),
            toolkit,
        )

    async def _calculate(
        state: Any,
    ) -> dict[str, Any]:
        return await calculate_scores(
            _to_dict(state),
            toolkit,
        )

    async def _benchmark(
        state: Any,
    ) -> dict[str, Any]:
        return await benchmark(
            _to_dict(state),
            toolkit,
        )

    async def _trends(
        state: Any,
    ) -> dict[str, Any]:
        return await trend_analysis(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(SecurityPostureScorerState)
    graph.add_node("collect_signals", _collect)
    graph.add_node("weight_categories", _weight)
    graph.add_node("calculate_scores", _calculate)
    graph.add_node("benchmark", _benchmark)
    graph.add_node("trend_analysis", _trends)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_signals")
    graph.add_edge(
        "collect_signals",
        "weight_categories",
    )
    graph.add_edge(
        "weight_categories",
        "calculate_scores",
    )
    graph.add_edge(
        "calculate_scores",
        "benchmark",
    )
    graph.add_edge(
        "benchmark",
        "trend_analysis",
    )
    graph.add_edge(
        "trend_analysis",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_security_posture_scorer_graph(
    signal_sources: Any | None = None,
    benchmark_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security Posture Scorer graph."""
    toolkit = SecurityPostureScorerToolkit(
        signal_sources=signal_sources,
        benchmark_api=benchmark_api,
    )
    return build_graph(toolkit)
