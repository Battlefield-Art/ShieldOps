"""Endpoint Hardening Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import EndpointHardeningAgentState
from .nodes import (
    apply_hardening,
    check_baseline,
    detect_deviations,
    generate_fixes,
    generate_report,
    scan_endpoints,
)
from .tools import EndpointHardeningAgentToolkit


def build_graph(toolkit: EndpointHardeningAgentToolkit):  # type: ignore[no-untyped-def]
    """Build the endpoint_hardening_agent agent graph (linear sequence)."""
    return build_linear_graph(
        EndpointHardeningAgentState,
        [
            ("scan_endpoints", scan_endpoints),
            ("check_baseline", check_baseline),
            ("detect_deviations", detect_deviations),
            ("generate_fixes", generate_fixes),
            ("apply_hardening", apply_hardening),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_endpoint_hardening_agent_graph(
    endpoint_api: Any | None = None,
    benchmark_db: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Endpoint Hardening Agent graph."""
    toolkit = EndpointHardeningAgentToolkit(
        endpoint_api=endpoint_api,
        benchmark_db=benchmark_db,
    )
    return build_graph(toolkit)
