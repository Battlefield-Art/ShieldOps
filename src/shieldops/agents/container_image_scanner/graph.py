"""Container Image Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import ContainerImageScannerState
from .nodes import (
    analyze_layers,
    check_compliance,
    discover_images,
    generate_report,
    prioritize_findings,
    scan_vulnerabilities,
)
from .tools import ContainerImageScannerToolkit


def build_graph(toolkit: ContainerImageScannerToolkit):  # type: ignore[no-untyped-def]
    """Build the container_image_scanner agent graph (linear sequence)."""
    return build_linear_graph(
        ContainerImageScannerState,
        [
            ("discover_images", discover_images),
            ("analyze_layers", analyze_layers),
            ("scan_vulnerabilities", scan_vulnerabilities),
            ("check_compliance", check_compliance),
            ("prioritize", prioritize_findings),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_container_image_scanner_graph(
    registry_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Container Image Scanner graph with deps."""
    toolkit = ContainerImageScannerToolkit(
        registry_client=registry_client,
    )
    return build_graph(toolkit)
