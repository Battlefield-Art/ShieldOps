"""LangGraph workflow definition for the Identity Graph Agent."""

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.identity_graph.models import IdentityGraphState
from shieldops.agents.identity_graph.nodes import (
    analyze_trust_chains,
    assess_risks,
    discover_identities,
    generate_remediations,
    map_relationships,
    report,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def has_high_risk(state: IdentityGraphState) -> str:
    """Route based on whether high-risk identities were found."""
    if state.error:
        return "report"
    high_risk_found = any(ra.risk_score >= 60 for ra in state.risk_assessments)
    over_privileged = len(state.over_privileged_identities) > 0
    if high_risk_found or over_privileged:
        return "generate_remediations"
    return "report"


def create_identity_graph() -> StateGraph[IdentityGraphState]:
    """Build the Identity Graph Agent LangGraph workflow.

    Workflow:
        discover_identities → map_relationships → analyze_trust_chains
            → assess_risks → [conditional: generate_remediations OR report]
            → report → END
    """
    graph = StateGraph(IdentityGraphState)

    _agent = "identity_graph"
    graph.add_node(
        "discover_identities",
        traced_node("identity_graph.discover_identities", _agent)(discover_identities),
    )
    graph.add_node(
        "map_relationships",
        traced_node("identity_graph.map_relationships", _agent)(map_relationships),
    )
    graph.add_node(
        "analyze_trust_chains",
        traced_node("identity_graph.analyze_trust_chains", _agent)(analyze_trust_chains),
    )
    graph.add_node(
        "assess_risks",
        traced_node("identity_graph.assess_risks", _agent)(assess_risks),
    )
    graph.add_node(
        "generate_remediations",
        traced_node("identity_graph.generate_remediations", _agent)(generate_remediations),
    )
    graph.add_node(
        "report",
        traced_node("identity_graph.report", _agent)(report),
    )

    # Define edges
    graph.set_entry_point("discover_identities")
    graph.add_edge("discover_identities", "map_relationships")
    graph.add_edge("map_relationships", "analyze_trust_chains")
    graph.add_edge("analyze_trust_chains", "assess_risks")
    graph.add_conditional_edges(
        "assess_risks",
        has_high_risk,
        {
            "generate_remediations": "generate_remediations",
            "report": "report",
        },
    )
    graph.add_edge("generate_remediations", "report")
    graph.add_edge("report", END)

    return graph
