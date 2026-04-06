"""Shadow API Detector Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import ShadowAPIDetectorState
from .nodes import (
    analyze_endpoints,
    auto_document,
    classify_risk,
    detect_shadow,
    discover_traffic,
    generate_report,
)
from .tools import ShadowAPIDetectorToolkit


def build_graph(toolkit: ShadowAPIDetectorToolkit):  # type: ignore[no-untyped-def]
    """Build the shadow_api_detector agent graph (linear sequence)."""
    return build_linear_graph(
        ShadowAPIDetectorState,
        [
            ("discover_traffic", discover_traffic),
            ("analyze_endpoints", analyze_endpoints),
            ("detect_shadow", detect_shadow),
            ("classify_risk", classify_risk),
            ("auto_document", auto_document),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_shadow_api_detector_graph(
    traffic_source: Any | None = None,
    api_registry: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Shadow API Detector graph."""
    toolkit = ShadowAPIDetectorToolkit(
        traffic_source=traffic_source,
        api_registry=api_registry,
    )
    return build_graph(toolkit)
