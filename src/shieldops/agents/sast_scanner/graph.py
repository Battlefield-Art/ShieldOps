"""SAST Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SASTScannerState
from .nodes import (
    analyze_dataflow,
    discover_files,
    generate_report,
    parse_ast,
    prioritize,
    scan_patterns,
)
from .tools import SASTScannerToolkit


def build_graph(toolkit: SASTScannerToolkit):  # type: ignore[no-untyped-def]
    """Build the sast_scanner agent graph (linear sequence)."""
    return build_linear_graph(
        SASTScannerState,
        [
            ("discover_files", discover_files),
            ("parse_ast", parse_ast),
            ("scan_patterns", scan_patterns),
            ("analyze_dataflow", analyze_dataflow),
            ("prioritize", prioritize),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_sast_scanner_graph(
    git_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the SAST Scanner graph with dependencies."""
    toolkit = SASTScannerToolkit(git_client=git_client)
    return build_graph(toolkit)
