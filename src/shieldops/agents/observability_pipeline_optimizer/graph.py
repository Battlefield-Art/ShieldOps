"""Observability Pipeline Optimizer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: ObservabilityPipelineOptimizerToolkit):  # type: ignore[no-untyped-def]
    """Build the observability_pipeline_optimizer agent graph (linear sequence)."""
    return build_linear_graph(
        ObservabilityPipelineOptimizerState,
        [
            ("audit_pipelines", audit_pipelines),
            ("analyze_cardinality", analyze_cardinality),
            ("optimize_sampling", optimize_sampling),
            ("reduce_costs", reduce_costs),
            ("validate_quality", validate_quality),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


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
