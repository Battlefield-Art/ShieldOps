"""Security Scorecard Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SecurityScorecardState
from .nodes import (
    calculate_composite,
    collect_domain_scores,
    compare_benchmarks,
    generate_insights,
    generate_report,
    track_trends,
)
from .tools import SecurityScorecardToolkit


def build_graph(toolkit: SecurityScorecardToolkit):  # type: ignore[no-untyped-def]
    """Build the security_scorecard agent graph (linear sequence)."""
    return build_linear_graph(
        SecurityScorecardState,
        [
            ("collect_domain_scores", collect_domain_scores),
            ("calculate_composite", calculate_composite),
            ("track_trends", track_trends),
            ("compare_benchmarks", compare_benchmarks),
            ("generate_insights", generate_insights),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_security_scorecard_graph(
    agent_registry: Any | None = None,
    metrics_store: Any | None = None,
    benchmark_db: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory: create the Security Scorecard graph."""
    toolkit = SecurityScorecardToolkit(
        agent_registry=agent_registry,
        metrics_store=metrics_store,
        benchmark_db=benchmark_db,
    )
    return build_graph(toolkit)
