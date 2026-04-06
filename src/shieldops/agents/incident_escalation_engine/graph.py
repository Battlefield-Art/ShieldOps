"""Incident Escalation Engine — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import IncidentEscalationEngineState
from .nodes import (
    assess_severity,
    determine_escalation,
    evaluate_impact,
    notify_responders,
    report,
    track_response,
)
from .tools import IncidentEscalationEngineToolkit


def build_graph(toolkit: IncidentEscalationEngineToolkit):  # type: ignore[no-untyped-def]
    """Build the incident_escalation_engine agent graph (linear sequence)."""
    return build_linear_graph(
        IncidentEscalationEngineState,
        [
            ("assess_severity", assess_severity),
            ("evaluate_impact", evaluate_impact),
            ("determine_escalation", determine_escalation),
            ("notify_responders", notify_responders),
            ("track_response", track_response),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_incident_escalation_engine_graph(
    notification_service: Any | None = None,
    oncall_service: Any | None = None,
) -> StateGraph:
    """Factory to create the escalation engine graph."""
    toolkit = IncidentEscalationEngineToolkit(
        notification_service=notification_service,
        oncall_service=oncall_service,
    )
    return build_graph(toolkit)
