"""Code Security Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import CodeSecurityScannerState
from .nodes import (
    discover_repositories,
    generate_report,
    prioritize_findings,
    scan_application_code,
    scan_dependencies,
    scan_iac,
)
from .tools import CodeSecurityScannerToolkit


def build_graph(toolkit: CodeSecurityScannerToolkit):  # type: ignore[no-untyped-def]
    """Build the code_security_scanner agent graph (linear sequence)."""
    return build_linear_graph(
        CodeSecurityScannerState,
        [
            ("discover_repositories", discover_repositories),
            ("scan_iac", scan_iac),
            ("scan_dependencies", scan_dependencies),
            ("scan_application_code", scan_application_code),
            ("prioritize_findings", prioritize_findings),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_code_security_scanner_graph(
    git_client: Any | None = None,
    registry_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Code Security Scanner graph with deps."""
    toolkit = CodeSecurityScannerToolkit(
        git_client=git_client,
        registry_client=registry_client,
    )
    return build_graph(toolkit)
