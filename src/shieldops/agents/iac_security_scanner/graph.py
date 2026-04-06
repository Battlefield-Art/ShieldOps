"""IaC Security Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import IACScannerState
from .nodes import (
    discover_templates,
    evaluate_policies,
    generate_report,
    parse_resources,
    prioritize_findings,
    scan_misconfigs,
)
from .tools import IACSecurityScannerToolkit


def build_graph(toolkit: IACSecurityScannerToolkit):  # type: ignore[no-untyped-def]
    """Build the iac_security_scanner agent graph (linear sequence)."""
    return build_linear_graph(
        IACScannerState,
        [
            ("discover_templates", discover_templates),
            ("parse_resources", parse_resources),
            ("scan_misconfigs", scan_misconfigs),
            ("evaluate_policies", evaluate_policies),
            ("prioritize", prioritize_findings),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_iac_security_scanner_graph(
    git_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the IaC Security Scanner graph with deps."""
    toolkit = IACSecurityScannerToolkit(git_client=git_client)
    return build_graph(toolkit)
