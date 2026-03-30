"""Incident Escalation Engine — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

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

_AGENT = "incident_escalation_engine"


def _check_error(
    state: IncidentEscalationEngineState,
) -> str:
    if state.error:
        return "report"
    return "continue"


def build_graph(
    toolkit: IncidentEscalationEngineToolkit,
) -> StateGraph:
    """Build the Incident Escalation Engine graph."""

    def _d(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _assess(s: Any) -> dict[str, Any]:
        return await assess_severity(_d(s))

    async def _impact(s: Any) -> dict[str, Any]:
        return await evaluate_impact(_d(s))

    async def _escalate(s: Any) -> dict[str, Any]:
        return await determine_escalation(_d(s))

    async def _notify(s: Any) -> dict[str, Any]:
        return await notify_responders(_d(s))

    async def _track(s: Any) -> dict[str, Any]:
        return await track_response(_d(s))

    async def _report(s: Any) -> dict[str, Any]:
        return await report(_d(s))

    g = StateGraph(IncidentEscalationEngineState)
    g.add_node(
        "assess_severity",
        traced_node("iesc.assess", _AGENT)(_assess),
    )
    g.add_node(
        "evaluate_impact",
        traced_node("iesc.impact", _AGENT)(_impact),
    )
    g.add_node(
        "determine_escalation",
        traced_node("iesc.escalate", _AGENT)(_escalate),
    )
    g.add_node(
        "notify_responders",
        traced_node("iesc.notify", _AGENT)(_notify),
    )
    g.add_node(
        "track_response",
        traced_node("iesc.track", _AGENT)(_track),
    )
    g.add_node(
        "report",
        traced_node("iesc.report", _AGENT)(_report),
    )

    g.set_entry_point("assess_severity")
    g.add_edge("assess_severity", "evaluate_impact")
    g.add_edge("evaluate_impact", "determine_escalation")
    g.add_edge(
        "determine_escalation",
        "notify_responders",
    )
    g.add_edge("notify_responders", "track_response")
    g.add_edge("track_response", "report")
    g.add_edge("report", END)

    return g


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
