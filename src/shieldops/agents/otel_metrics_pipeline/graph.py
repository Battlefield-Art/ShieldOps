"""OTel Metrics Pipeline Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import OTelMetricsPipelineState
from .nodes import (
    configure_pipeline,
    discover_endpoints,
    optimize_cardinality,
    validate_coverage,
)
from .tools import OTelMetricsPipelineToolkit


def build_graph(toolkit: OTelMetricsPipelineToolkit):  # type: ignore[no-untyped-def]
    """Build the otel_metrics_pipeline agent graph (linear sequence)."""
    return build_linear_graph(
        OTelMetricsPipelineState,
        [
            ("discover", discover_endpoints),
            ("configure", configure_pipeline),
            ("optimize", optimize_cardinality),
            ("validate", validate_coverage),
        ],
        toolkit=toolkit,
    )


def create_otel_metrics_pipeline_graph(
    k8s_client: Any | None = None,
    repository: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create and return the OTel Metrics Pipeline graph.

    This is the main public entry point exported from __init__.py.
    """
    toolkit = OTelMetricsPipelineToolkit(
        k8s_client=k8s_client,
        repository=repository,
    )
    return build_graph(toolkit)
