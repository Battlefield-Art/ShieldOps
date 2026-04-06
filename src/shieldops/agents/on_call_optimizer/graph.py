"""On-Call Optimizer — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import OnCallOptimizerState
from .nodes import (
    analyze_schedules,
    detect_burnout,
    evaluate_load,
    optimize_rotation,
    recommend_changes,
    report,
)
from .tools import OnCallOptimizerToolkit


def build_graph(toolkit: OnCallOptimizerToolkit):  # type: ignore[no-untyped-def]
    """Build the on_call_optimizer agent graph (linear sequence)."""
    return build_linear_graph(
        OnCallOptimizerState,
        [
            ("analyze_schedules", analyze_schedules),
            ("evaluate_load", evaluate_load),
            ("detect_burnout", detect_burnout),
            ("optimize_rotation", optimize_rotation),
            ("recommend_changes", recommend_changes),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_on_call_optimizer_graph(
    schedule_service: Any | None = None,
    incident_service: Any | None = None,
) -> StateGraph:
    """Factory to create the on-call optimizer graph."""
    toolkit = OnCallOptimizerToolkit(
        schedule_service=schedule_service,
        incident_service=incident_service,
    )
    return build_graph(toolkit)
