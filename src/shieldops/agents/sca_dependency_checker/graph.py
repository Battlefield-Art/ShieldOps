"""SCA Dependency Checker Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SCADependencyCheckerState
from .nodes import (
    check_licenses,
    discover_manifests,
    generate_report,
    match_cves,
    parse_dependencies,
    prioritize_findings,
)
from .tools import SCADependencyCheckerToolkit


def build_graph(toolkit: SCADependencyCheckerToolkit):  # type: ignore[no-untyped-def]
    """Build the sca_dependency_checker agent graph (linear sequence)."""
    return build_linear_graph(
        SCADependencyCheckerState,
        [
            ("discover_manifests", discover_manifests),
            ("parse_dependencies", parse_dependencies),
            ("match_cves", match_cves),
            ("check_licenses", check_licenses),
            ("prioritize", prioritize_findings),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_sca_dependency_checker_graph(
    registry_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the SCA Dependency Checker graph with deps."""
    toolkit = SCADependencyCheckerToolkit(
        registry_client=registry_client,
    )
    return build_graph(toolkit)
