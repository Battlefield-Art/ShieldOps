"""Predictive Scaler Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import PredictiveScalerState
from .nodes import (
    analyze_patterns,
    collect_metrics,
    execute_scaling,
    generate_report,
    plan_scaling,
    predict_demand,
)
from .tools import PredictiveScalerToolkit


def build_graph(toolkit: PredictiveScalerToolkit):  # type: ignore[no-untyped-def]
    """Build the predictive_scaler agent graph (linear sequence)."""
    return build_linear_graph(
        PredictiveScalerState,
        [
            ("collect_metrics", collect_metrics),
            ("analyze_patterns", analyze_patterns),
            ("predict_demand", predict_demand),
            ("plan_scaling", plan_scaling),
            ("execute_scaling", execute_scaling),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_predictive_scaler_graph(
    metrics_api: Any | None = None,
    infra_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Predictive Scaler graph."""
    toolkit = PredictiveScalerToolkit(
        metrics_api=metrics_api,
        infra_api=infra_api,
    )
    return build_graph(toolkit)
