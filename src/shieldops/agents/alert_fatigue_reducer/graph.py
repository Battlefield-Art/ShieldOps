"""Alert Fatigue Reducer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import AlertFatigueReducerState
from .nodes import (
    analyze_noise,
    collect_alerts,
    detect_fatigue,
    generate_report,
    tune_rules,
    validate_changes,
)
from .tools import AlertFatigueReducerToolkit


def build_graph(toolkit: AlertFatigueReducerToolkit):  # type: ignore[no-untyped-def]
    """Build the alert_fatigue_reducer agent graph (linear sequence)."""
    return build_linear_graph(
        AlertFatigueReducerState,
        [
            ("collect_alerts", collect_alerts),
            ("analyze_noise", analyze_noise),
            ("detect_fatigue", detect_fatigue),
            ("tune_rules", tune_rules),
            ("validate", validate_changes),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_alert_fatigue_reducer_graph(
    siem_client: Any | None = None,
    soar_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Alert Fatigue Reducer graph."""
    toolkit = AlertFatigueReducerToolkit(
        siem_client=siem_client,
        soar_client=soar_client,
    )
    return build_graph(toolkit)
