"""Security Scorecard Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecurityScorecardState
from .nodes import (
    calculate_composite,
    collect_domain_scores,
    compare_benchmarks,
    generate_insights,
    generate_report,
    track_trends,
)
from .tools import SecurityScorecardToolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if hasattr(state, "model_dump"):
        return state.model_dump()
    return dict(state) if not isinstance(state, dict) else state


def build_graph(
    toolkit: SecurityScorecardToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Scorecard agent graph."""

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_domain_scores(
            _to_dict(state),
            toolkit,
        )

    async def _composite(
        state: Any,
    ) -> dict[str, Any]:
        return await calculate_composite(
            _to_dict(state),
            toolkit,
        )

    async def _trends(
        state: Any,
    ) -> dict[str, Any]:
        return await track_trends(
            _to_dict(state),
            toolkit,
        )

    async def _benchmarks(
        state: Any,
    ) -> dict[str, Any]:
        return await compare_benchmarks(
            _to_dict(state),
            toolkit,
        )

    async def _insights(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_insights(
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

    graph = StateGraph(SecurityScorecardState)
    graph.add_node(
        "collect_domain_scores",
        _collect,
    )
    graph.add_node(
        "calculate_composite",
        _composite,
    )
    graph.add_node("track_trends", _trends)
    graph.add_node(
        "compare_benchmarks",
        _benchmarks,
    )
    graph.add_node(
        "generate_insights",
        _insights,
    )
    graph.add_node("generate_report", _report)

    graph.set_entry_point("collect_domain_scores")
    graph.add_edge(
        "collect_domain_scores",
        "calculate_composite",
    )
    graph.add_edge(
        "calculate_composite",
        "track_trends",
    )
    graph.add_edge(
        "track_trends",
        "compare_benchmarks",
    )
    graph.add_edge(
        "compare_benchmarks",
        "generate_insights",
    )
    graph.add_edge(
        "generate_insights",
        "generate_report",
    )
    graph.add_edge("generate_report", END)

    return graph


def create_security_scorecard_graph(
    agent_registry: Any | None = None,
    metrics_store: Any | None = None,
    benchmark_db: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory: create the Security Scorecard graph."""
    toolkit = SecurityScorecardToolkit(
        agent_registry=agent_registry,
        metrics_store=metrics_store,
        benchmark_db=benchmark_db,
    )
    return build_graph(toolkit)
