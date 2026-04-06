"""OTel Semantic Conventions Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import OTelSemanticState
from .nodes import (
    analyze_violations,
    generate_fixes,
    load_rules,
    scan_services,
)
from .tools import OTelSemanticToolkit


def build_graph(toolkit: OTelSemanticToolkit):  # type: ignore[no-untyped-def]
    """Build the otel_semantic agent graph (linear sequence)."""
    return build_linear_graph(
        OTelSemanticState,
        [
            ("load_rules", load_rules),
            ("scan", scan_services),
            ("analyze", analyze_violations),
            ("generate_fixes", generate_fixes),
        ],
        toolkit=toolkit,
    )


def create_otel_semantic_graph(
    telemetry_client: Any | None = None,
    repository: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create and return the OTel Semantic Conventions graph.

    This is the main public entry point exported from __init__.py.
    """
    toolkit = OTelSemanticToolkit(
        telemetry_client=telemetry_client,
        repository=repository,
    )
    return build_graph(toolkit)
