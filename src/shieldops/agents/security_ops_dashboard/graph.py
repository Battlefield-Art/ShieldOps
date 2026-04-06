"""Security Ops Dashboard Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SecurityOpsDashboardState
from .nodes import (
    build_views,
    calculate_kpis,
    collect_metrics,
    detect_anomalies,
    generate_insights,
    generate_report,
)
from .tools import SecurityOpsDashboardToolkit


def build_graph(toolkit: SecurityOpsDashboardToolkit):  # type: ignore[no-untyped-def]
    """Build the security_ops_dashboard agent graph (linear sequence)."""
    return build_linear_graph(
        SecurityOpsDashboardState,
        [
            ("collect_metrics", collect_metrics),
            ("calculate_kpis", calculate_kpis),
            ("detect_anomalies", detect_anomalies),
            ("generate_insights", generate_insights),
            ("build_views", build_views),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_security_ops_dashboard_graph(
    metrics_api: Any | None = None,
    dashboard_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security Ops Dashboard graph."""
    toolkit = SecurityOpsDashboardToolkit(
        metrics_api=metrics_api,
        dashboard_api=dashboard_api,
    )
    return build_graph(toolkit)
