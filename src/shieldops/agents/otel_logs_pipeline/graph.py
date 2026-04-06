"""OTel Logs Pipeline Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import OTelLogsPipelineState
from .nodes import (
    configure_pipeline,
    discover_sources,
    test_parsing,
    validate_correlation,
)
from .tools import OTelLogsPipelineToolkit


def build_graph(toolkit: OTelLogsPipelineToolkit):  # type: ignore[no-untyped-def]
    """Build the otel_logs_pipeline agent graph (linear sequence)."""
    return build_linear_graph(
        OTelLogsPipelineState,
        [
            ("discover", discover_sources),
            ("configure", configure_pipeline),
            ("test_parsing", test_parsing),
            ("validate", validate_correlation),
        ],
        toolkit=toolkit,
    )


def create_otel_logs_pipeline_graph(
    k8s_client: Any | None = None,
    repository: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create and return the OTel Logs Pipeline graph.

    This is the main public entry point exported from __init__.py.
    """
    toolkit = OTelLogsPipelineToolkit(
        k8s_client=k8s_client,
        repository=repository,
    )
    return build_graph(toolkit)
