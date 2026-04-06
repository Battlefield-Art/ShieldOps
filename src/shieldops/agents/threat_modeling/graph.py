"""Threat Modeling Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import ThreatModelingState
from .nodes import (
    analyze_threats,
    assess_risk,
    discover_architecture,
    recommend_mitigations,
)
from .tools import ThreatModelingToolkit


def build_graph(toolkit: ThreatModelingToolkit):  # type: ignore[no-untyped-def]
    """Build the threat_modeling agent graph (linear sequence)."""
    return build_linear_graph(
        ThreatModelingState,
        [
            ("discover_architecture", discover_architecture),
            ("analyze_threats", analyze_threats),
            ("assess_risk", assess_risk),
            ("recommend_mitigations", recommend_mitigations),
        ],
        toolkit=toolkit,
    )


def create_threat_modeling_graph(
    rba_client: Any | None = None,
    architecture_registry: Any | None = None,
    threat_intel: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Threat Modeling agent graph with dependencies."""
    toolkit = ThreatModelingToolkit(
        rba_client=rba_client,
        architecture_registry=architecture_registry,
        threat_intel=threat_intel,
    )
    return build_graph(toolkit)
