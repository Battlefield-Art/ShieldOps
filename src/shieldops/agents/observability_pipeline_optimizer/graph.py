"""Observability Pipeline Optimizer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ObservabilityPipelineOptimizerState
from .nodes import (
    analyze_cardinality,
    audit_pipelines,
    generate_report,
    optimize_sampling,
    reduce_costs,
    validate_quality,
)
from .tools import ObservabilityPipelineOptimizerToolkit


def build_graph(
    toolkit: ObservabilityPipelineOptimizerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Observability Pipeline Optimizer graph.

    Flow:
        audit_pipelines -> analyze_cardinality
        -> optimize_sampling -> reduce_costs
        -> validate_quality -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _audit(
        state: Any,
    ) -> dict[str, Any]:
        return await audit_pipelines(
            _to_dict(state),
            toolkit,
        )

    async def _cardinality(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_cardinality(
            _to_dict(state),
            toolkit,
        )

    async def _sampling(
        state: Any,
    ) -> dict[str, Any]:
        return await optimize_sampling(
            _to_dict(state),
            toolkit,
        )

    async def _costs(
        state: Any,
    ) -> dict[str, Any]:
        return await reduce_costs(
            _to_dict(state),
            toolkit,
        )

    async def _quality(
        state: Any,
    ) -> dict[str, Any]:
        return await validate_quality(
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

    graph = StateGraph(
        ObservabilityPipelineOptimizerState,
    )
    graph.add_node("audit_pipelines", _audit)
    graph.add_node("analyze_cardinality", _cardinality)
    graph.add_node("optimize_sampling", _sampling)
    graph.add_node("reduce_costs", _costs)
    graph.add_node("validate_quality", _quality)
    graph.add_node("report", _report)

    graph.set_entry_point("audit_pipelines")
    graph.add_edge(
        "audit_pipelines",
        "analyze_cardinality",
    )
    graph.add_edge(
        "analyze_cardinality",
        "optimize_sampling",
    )
    graph.add_edge(
        "optimize_sampling",
        "reduce_costs",
    )
    graph.add_edge(
        "reduce_costs",
        "validate_quality",
    )
    graph.add_edge(
        "validate_quality",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_observability_pipeline_optimizer_graph(
    otel_api: Any | None = None,
    vendor_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Observability Pipeline Optimizer."""
    toolkit = ObservabilityPipelineOptimizerToolkit(
        otel_api=otel_api,
        vendor_api=vendor_api,
    )
    return build_graph(toolkit)
