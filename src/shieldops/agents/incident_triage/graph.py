"""LangGraph workflow definition for the Incident Triage Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.incident_triage.models import IncidentTriageState
from shieldops.agents.incident_triage.nodes import (
    classify,
    deduplicate,
    enrich,
    generate_report,
    ingest,
    route,
)
from shieldops.agents.tracing import traced_node

_AGENT = "incident_triage"


def create_incident_triage_graph() -> StateGraph:
    """Build the Incident Triage Agent LangGraph workflow.

    Workflow:
        ingest -> classify -> enrich -> deduplicate -> route -> generate_report -> END
    """
    graph = StateGraph(IncidentTriageState)

    graph.add_node(
        "ingest",
        traced_node("incident_triage.ingest", _AGENT)(ingest),
    )
    graph.add_node(
        "classify",
        traced_node("incident_triage.classify", _AGENT)(classify),
    )
    graph.add_node(
        "enrich",
        traced_node("incident_triage.enrich", _AGENT)(enrich),
    )
    graph.add_node(
        "deduplicate",
        traced_node("incident_triage.deduplicate", _AGENT)(deduplicate),
    )
    graph.add_node(
        "route",
        traced_node("incident_triage.route", _AGENT)(route),
    )
    graph.add_node(
        "generate_report",
        traced_node("incident_triage.generate_report", _AGENT)(generate_report),
    )

    # Linear pipeline: ingest -> classify -> enrich -> deduplicate -> route -> report
    graph.set_entry_point("ingest")
    graph.add_edge("ingest", "classify")
    graph.add_edge("classify", "enrich")
    graph.add_edge("enrich", "deduplicate")
    graph.add_edge("deduplicate", "route")
    graph.add_edge("route", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
