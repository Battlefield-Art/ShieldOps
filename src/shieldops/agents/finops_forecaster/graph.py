"""FinOps Forecaster Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import FinopsForecasterState
from .nodes import (
    analyze_trends,
    collect_history,
    detect_anomalies,
    forecast_spend,
    generate_report,
    recommend_commitments,
)
from .tools import FinopsForecasterToolkit


def build_graph(toolkit: FinopsForecasterToolkit):  # type: ignore[no-untyped-def]
    """Build the finops_forecaster agent graph (linear sequence)."""
    return build_linear_graph(
        FinopsForecasterState,
        [
            ("collect_history", collect_history),
            ("analyze_trends", analyze_trends),
            ("forecast_spend", forecast_spend),
            ("detect_anomalies", detect_anomalies),
            ("recommend_commitments", recommend_commitments),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_finops_forecaster_graph(
    billing_api: Any | None = None,
    cloud_provider: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the FinOps Forecaster graph."""
    toolkit = FinopsForecasterToolkit(
        billing_api=billing_api,
        cloud_provider=cloud_provider,
    )
    return build_graph(toolkit)
