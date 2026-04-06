"""CNAPP Analyzer Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import CNAPPAnalyzerState
from .nodes import (
    analyze_identity_entitlements,
    assess_workload_protection,
    correlate_risks,
    generate_report,
    scan_cloud_posture,
    scan_code_security,
)
from .tools import CNAPPAnalyzerToolkit


def build_graph(toolkit: CNAPPAnalyzerToolkit):  # type: ignore[no-untyped-def]
    """Build the cnapp_analyzer agent graph (linear sequence)."""
    return build_linear_graph(
        CNAPPAnalyzerState,
        [
            ("scan_cloud_posture", scan_cloud_posture),
            ("assess_workload_protection", assess_workload_protection),
            ("analyze_identity_entitlements", analyze_identity_entitlements),
            ("scan_code_security", scan_code_security),
            ("correlate_risks", correlate_risks),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_cnapp_analyzer_graph(
    cloud_clients: Any | None = None,
    workload_scanner: Any | None = None,
    identity_analyzer: Any | None = None,
    code_scanner: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the CNAPP Analyzer graph with deps."""
    toolkit = CNAPPAnalyzerToolkit(
        cloud_clients=cloud_clients,
        workload_scanner=workload_scanner,
        identity_analyzer=identity_analyzer,
        code_scanner=code_scanner,
    )
    return build_graph(toolkit)
