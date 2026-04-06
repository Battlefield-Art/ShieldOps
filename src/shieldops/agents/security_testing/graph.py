"""Automated Security Testing Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SecurityTestingState
from .nodes import (
    analyze_findings,
    define_scope,
    execute_scans,
    generate_report,
)
from .tools import SecurityTestingToolkit


def build_graph(toolkit: SecurityTestingToolkit):  # type: ignore[no-untyped-def]
    """Build the security_testing agent graph (linear sequence)."""
    return build_linear_graph(
        SecurityTestingState,
        [
            ("define_scope", define_scope),
            ("execute_scans", execute_scans),
            ("analyze_findings", analyze_findings),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_security_testing_graph(
    scanner_client: Any | None = None,
    config_client: Any | None = None,
    credential_store: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Automated Security Testing agent graph with dependencies."""
    toolkit = SecurityTestingToolkit(
        scanner_client=scanner_client,
        config_client=config_client,
        credential_store=credential_store,
    )
    return build_graph(toolkit)
