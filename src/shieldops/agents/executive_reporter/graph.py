"""Executive Reporter Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ExecutiveReporterState
from .nodes import (
    analyze_trends,
    collect_metrics,
    compose_report,
    generate_recommendations,
    generate_report,
    summarize_findings,
)
from .tools import ExecutiveReporterToolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if hasattr(state, "model_dump"):
        return state.model_dump()
    return dict(state) if not isinstance(state, dict) else state


def build_graph(
    toolkit: ExecutiveReporterToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Executive Reporter agent graph."""

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_metrics(
            _to_dict(state),
            toolkit,
        )

    async def _trends(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_trends(
            _to_dict(state),
            toolkit,
        )

    async def _findings(
        state: Any,
    ) -> dict[str, Any]:
        return await summarize_findings(
            _to_dict(state),
            toolkit,
        )

    async def _recs(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_recommendations(
            _to_dict(state),
            toolkit,
        )

    async def _compose(
        state: Any,
    ) -> dict[str, Any]:
        return await compose_report(
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

    graph = StateGraph(ExecutiveReporterState)
    graph.add_node("collect_metrics", _collect)
    graph.add_node("analyze_trends", _trends)
    graph.add_node(
        "summarize_findings",
        _findings,
    )
    graph.add_node(
        "generate_recommendations",
        _recs,
    )
    graph.add_node("compose_report", _compose)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("collect_metrics")
    graph.add_edge(
        "collect_metrics",
        "analyze_trends",
    )
    graph.add_edge(
        "analyze_trends",
        "summarize_findings",
    )
    graph.add_edge(
        "summarize_findings",
        "generate_recommendations",
    )
    graph.add_edge(
        "generate_recommendations",
        "compose_report",
    )
    graph.add_edge(
        "compose_report",
        "generate_report",
    )
    graph.add_edge("generate_report", END)

    return graph


def create_executive_reporter_graph(
    agent_registry: Any | None = None,
    metrics_store: Any | None = None,
    findings_db: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory: create the Executive Reporter graph."""
    toolkit = ExecutiveReporterToolkit(
        agent_registry=agent_registry,
        metrics_store=metrics_store,
        findings_db=findings_db,
    )
    return build_graph(toolkit)
