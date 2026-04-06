"""Security Posture Scorer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SecurityPostureScorerState
from .nodes import (
    benchmark,
    calculate_scores,
    collect_signals,
    generate_report,
    trend_analysis,
    weight_categories,
)
from .tools import SecurityPostureScorerToolkit


def build_graph(toolkit: SecurityPostureScorerToolkit):  # type: ignore[no-untyped-def]
    """Build the security_posture_scorer agent graph (linear sequence)."""
    return build_linear_graph(
        SecurityPostureScorerState,
        [
            ("collect_signals", collect_signals),
            ("weight_categories", weight_categories),
            ("calculate_scores", calculate_scores),
            ("benchmark", benchmark),
            ("trend_analysis", trend_analysis),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_security_posture_scorer_graph(
    signal_sources: Any | None = None,
    benchmark_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security Posture Scorer graph."""
    toolkit = SecurityPostureScorerToolkit(
        signal_sources=signal_sources,
        benchmark_api=benchmark_api,
    )
    return build_graph(toolkit)
