"""Privilege Escalation Detector Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import PrivilegeEscalationDetectorState
from .nodes import (
    assess_risk,
    classify_escalations,
    collect_events,
    correlate_identities,
    generate_report,
    respond,
)
from .tools import PrivilegeEscalationToolkit


def _has_findings(state: Any) -> str:
    """Route based on whether escalation findings exist."""
    if hasattr(state, "escalation_findings"):
        findings = state.escalation_findings
    else:
        findings = state.get("escalation_findings", [])
    if findings:
        return "respond"
    return "report"


def build_graph(
    toolkit: PrivilegeEscalationToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Privilege Escalation Detector graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect_events(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_events(_to_dict(state), toolkit)

    async def _classify_escalations(
        state: Any,
    ) -> dict[str, Any]:
        return await classify_escalations(_to_dict(state), toolkit)

    async def _correlate_identities(
        state: Any,
    ) -> dict[str, Any]:
        return await correlate_identities(_to_dict(state), toolkit)

    async def _assess_risk(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_risk(_to_dict(state), toolkit)

    async def _respond(state: Any) -> dict[str, Any]:
        return await respond(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(PrivilegeEscalationDetectorState)
    graph.add_node("collect_events", _collect_events)
    graph.add_node("classify_escalations", _classify_escalations)
    graph.add_node("correlate_identities", _correlate_identities)
    graph.add_node("assess_risk", _assess_risk)
    graph.add_node("respond", _respond)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_events")
    graph.add_edge("collect_events", "classify_escalations")
    graph.add_edge("classify_escalations", "correlate_identities")
    graph.add_edge("correlate_identities", "assess_risk")
    graph.add_conditional_edges(
        "assess_risk",
        _has_findings,
        {"respond": "respond", "report": "report"},
    )
    graph.add_edge("respond", "report")
    graph.add_edge("report", END)

    return graph


def create_privilege_escalation_detector_graph(
    identity_store: Any | None = None,
    cloud_connectors: dict[str, Any] | None = None,
    response_engine: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Privilege Escalation Detector graph."""
    toolkit = PrivilegeEscalationToolkit(
        identity_store=identity_store,
        cloud_connectors=cloud_connectors,
        response_engine=response_engine,
    )
    return build_graph(toolkit)
