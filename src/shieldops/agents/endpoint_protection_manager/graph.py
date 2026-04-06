"""Endpoint Protection Manager Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import EndpointProtectionManagerState
from .nodes import (
    assess_patches,
    check_agents,
    generate_report,
    inventory_endpoints,
    remediate_gaps,
    scan_malware,
)
from .tools import EndpointProtectionManagerToolkit


def build_graph(toolkit: EndpointProtectionManagerToolkit):  # type: ignore[no-untyped-def]
    """Build the endpoint_protection_manager agent graph (linear sequence)."""
    return build_linear_graph(
        EndpointProtectionManagerState,
        [
            ("inventory_endpoints", inventory_endpoints),
            ("check_agents", check_agents),
            ("assess_patches", assess_patches),
            ("scan_malware", scan_malware),
            ("remediate_gaps", remediate_gaps),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_endpoint_protection_manager_graph(
    edr_api: Any | None = None,
    cmdb_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Endpoint Protection Manager graph."""
    toolkit = EndpointProtectionManagerToolkit(
        edr_api=edr_api,
        cmdb_api=cmdb_api,
    )
    return build_graph(toolkit)
