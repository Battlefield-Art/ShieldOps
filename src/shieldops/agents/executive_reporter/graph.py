"""Executive Reporter Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import ExecutiveReporterState
from .nodes import (
    analyze_trends,
    collect_metrics,
    compose_report,
    generate_recommendations,
    generate_report,
    summarize_findings,
)
from .tools import ExecutiveReporterToolkit


def build_graph(toolkit: ExecutiveReporterToolkit):  # type: ignore[no-untyped-def]
    """Build the executive_reporter agent graph (linear sequence)."""
    return build_linear_graph(
        ExecutiveReporterState,
        [
            ("collect_metrics", collect_metrics),
            ("analyze_trends", analyze_trends),
            ("summarize_findings", summarize_findings),
            ("generate_recommendations", generate_recommendations),
            ("compose_report", compose_report),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_executive_reporter_graph(
    agent_registry: Any | None = None,
    metrics_store: Any | None = None,
    findings_db: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory: create the Executive Reporter graph."""
    toolkit = ExecutiveReporterToolkit(
        agent_registry=agent_registry,
        metrics_store=metrics_store,
        findings_db=findings_db,
    )
    return build_graph(toolkit)
