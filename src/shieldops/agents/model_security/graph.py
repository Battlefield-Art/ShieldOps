"""Model Security Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import ModelSecurityState
from .nodes import (
    assess_integrity,
    detect_backdoors,
    evaluate_risks,
    scan_models,
    verify_provenance,
)
from .tools import ModelSecurityToolkit


def build_graph(toolkit: ModelSecurityToolkit):  # type: ignore[no-untyped-def]
    """Build the model_security agent graph (linear sequence)."""
    return build_linear_graph(
        ModelSecurityState,
        [
            ("scan_models", scan_models),
            ("verify_provenance", verify_provenance),
            ("detect_backdoors", detect_backdoors),
            ("assess_integrity", assess_integrity),
            ("evaluate_risks", evaluate_risks),
        ],
        toolkit=toolkit,
    )


def create_model_security_graph(
    model_registry_client: Any | None = None,
    provenance_service: Any | None = None,
    scanning_engine: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Model Security agent graph with dependencies."""
    toolkit = ModelSecurityToolkit(
        model_registry_client=model_registry_client,
        provenance_service=provenance_service,
        scanning_engine=scanning_engine,
    )
    return build_graph(toolkit)
