"""LangGraph workflow definition for the Threat Attribution Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.threat_attribution.models import (
    ThreatAttributionState,
)
from shieldops.agents.threat_attribution.nodes import (
    assess_confidence,
    collect_evidence,
    generate_report,
    map_ttps,
    profile_actor,
)
from shieldops.agents.tracing import traced_node

_AGENT = "threat_attribution"


def _route_or_report(
    state: ThreatAttributionState,
) -> str:
    """If an error has been recorded, skip straight to report."""
    if state.error:
        return "report"
    return "next"


def create_threat_attribution_graph() -> StateGraph:
    """Build the Threat Attribution LangGraph workflow.

    Flow:
        collect_evidence -> map_ttps -> profile_actor
        -> assess_confidence -> generate_report -> END

    Any node that sets ``state.error`` causes a conditional
    edge to jump directly to *generate_report* so partial
    results are still captured.
    """
    graph = StateGraph(ThreatAttributionState)

    # -- nodes ---------------------------------------------------
    graph.add_node(
        "collect_evidence",
        traced_node(
            "threat_attribution.collect_evidence",
            _AGENT,
        )(collect_evidence),
    )
    graph.add_node(
        "map_ttps",
        traced_node(
            "threat_attribution.map_ttps",
            _AGENT,
        )(map_ttps),
    )
    graph.add_node(
        "profile_actor",
        traced_node(
            "threat_attribution.profile_actor",
            _AGENT,
        )(profile_actor),
    )
    graph.add_node(
        "assess_confidence",
        traced_node(
            "threat_attribution.assess_confidence",
            _AGENT,
        )(assess_confidence),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            "threat_attribution.generate_report",
            _AGENT,
        )(generate_report),
    )

    # -- edges ---------------------------------------------------
    graph.set_entry_point("collect_evidence")

    graph.add_conditional_edges(
        "collect_evidence",
        _route_or_report,
        {"next": "map_ttps", "report": "generate_report"},
    )
    graph.add_conditional_edges(
        "map_ttps",
        _route_or_report,
        {
            "next": "profile_actor",
            "report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "profile_actor",
        _route_or_report,
        {
            "next": "assess_confidence",
            "report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "assess_confidence",
        _route_or_report,
        {
            "next": "generate_report",
            "report": "generate_report",
        },
    )
    graph.add_edge("generate_report", END)

    return graph
