"""Endpoint DLP Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import EndpointDLPState
from .nodes import (
    classify_sensitivity,
    detect_data_movement,
    enforce_policies,
    investigate_violations,
    monitor_endpoints,
    report,
)
from .tools import EndpointDLPToolkit


def build_graph(toolkit: EndpointDLPToolkit):  # type: ignore[no-untyped-def]
    """Build the endpoint_dlp agent graph (linear sequence)."""
    return build_linear_graph(
        EndpointDLPState,
        [
            ("monitor_endpoints", monitor_endpoints),
            ("detect_data_movement", detect_data_movement),
            ("classify_sensitivity", classify_sensitivity),
            ("enforce_policies", enforce_policies),
            ("investigate_violations", investigate_violations),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_endpoint_dlp_graph(
    edr_client: Any | None = None,
    dlp_engine: Any | None = None,
    siem_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Endpoint DLP graph."""
    toolkit = EndpointDLPToolkit(
        edr_client=edr_client,
        dlp_engine=dlp_engine,
        siem_client=siem_client,
    )
    return build_graph(toolkit)
