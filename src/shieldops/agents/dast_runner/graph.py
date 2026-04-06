"""DAST Runner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import DASTRunnerState
from .nodes import (
    analyze_responses,
    crawl_application,
    discover_endpoints,
    fuzz_parameters,
    generate_report,
    test_authentication,
)
from .tools import DASTRunnerToolkit


def build_graph(toolkit: DASTRunnerToolkit):  # type: ignore[no-untyped-def]
    """Build the dast_runner agent graph (linear sequence)."""
    return build_linear_graph(
        DASTRunnerState,
        [
            ("discover_endpoints", discover_endpoints),
            ("crawl_application", crawl_application),
            ("test_authentication", test_authentication),
            ("fuzz_parameters", fuzz_parameters),
            ("analyze_responses", analyze_responses),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_dast_runner_graph(
    http_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the DAST Runner graph with dependencies."""
    toolkit = DASTRunnerToolkit(http_client=http_client)
    return build_graph(toolkit)
