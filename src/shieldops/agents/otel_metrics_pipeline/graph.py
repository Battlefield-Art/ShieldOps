"""OTel Metrics Pipeline Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import OTelMetricsPipelineState
from .nodes import (
    configure_pipeline,
    discover_endpoints,
    optimize_cardinality,
    validate_coverage,
)
from .tools import OTelMetricsPipelineToolkit


def build_graph(toolkit: OTelMetricsPipelineToolkit) -> StateGraph:
    """Build the OTel Metrics Pipeline agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_endpoints(_to_dict(state), toolkit)

    async def _configure(state: Any) -> dict[str, Any]:
        return await configure_pipeline(_to_dict(state), toolkit)

    async def _optimize(state: Any) -> dict[str, Any]:
        return await optimize_cardinality(_to_dict(state), toolkit)

    async def _validate(state: Any) -> dict[str, Any]:
        return await validate_coverage(_to_dict(state), toolkit)

    graph = StateGraph(OTelMetricsPipelineState)
    graph.add_node("discover", _discover)
    graph.add_node("configure", _configure)
    graph.add_node("optimize", _optimize)
    graph.add_node("validate", _validate)

    graph.set_entry_point("discover")
    graph.add_edge("discover", "configure")
    graph.add_edge("configure", "optimize")
    graph.add_edge("optimize", "validate")
    graph.add_edge("validate", END)

    return graph


def create_otel_metrics_pipeline_graph(
    k8s_client: Any | None = None,
    repository: Any | None = None,
) -> StateGraph:
    """Create and return the OTel Metrics Pipeline graph.

    This is the main public entry point exported from __init__.py.
    """
    toolkit = OTelMetricsPipelineToolkit(
        k8s_client=k8s_client,
        repository=repository,
    )
    return build_graph(toolkit)
