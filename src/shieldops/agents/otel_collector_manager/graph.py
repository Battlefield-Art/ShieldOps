"""OTel Collector Manager Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import OTelCollectorManagerState
from .nodes import (
    assess_requirements,
    deploy_and_verify,
    generate_config,
    monitor_health,
)
from .tools import OTelCollectorManagerToolkit


def build_graph(toolkit: OTelCollectorManagerToolkit):  # type: ignore[no-untyped-def]
    """Build the otel_collector_manager agent graph (linear sequence)."""
    return build_linear_graph(
        OTelCollectorManagerState,
        [
            ("assess", assess_requirements),
            ("generate", generate_config),
            ("deploy", deploy_and_verify),
            ("monitor", monitor_health),
        ],
        toolkit=toolkit,
    )


def create_otel_collector_manager_graph(
    k8s_client: Any | None = None,
    repository: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create and return the OTel Collector Manager graph.

    This is the main public entry point exported from __init__.py.
    """
    toolkit = OTelCollectorManagerToolkit(
        k8s_client=k8s_client,
        repository=repository,
    )
    return build_graph(toolkit)
