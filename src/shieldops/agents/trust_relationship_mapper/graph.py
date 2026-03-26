"""LangGraph workflow for the Trust Relationship Mapper Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node
from shieldops.agents.trust_relationship_mapper.models import (
    TrustRelationshipMapperState,
)
from shieldops.agents.trust_relationship_mapper.nodes import (
    analyze_delegation_chains,
    assess_risk,
    detect_trust_abuse,
    discover_trust_boundaries,
    generate_report,
    map_federation,
)

_AGENT = "trust_relationship_mapper"


def _has_boundaries(
    state: TrustRelationshipMapperState,
) -> str:
    """Route based on whether boundaries exist."""
    if state.error:
        return END
    if not state.trust_boundaries:
        return "generate_report"
    return "map_federation"


def _has_abuses(
    state: TrustRelationshipMapperState,
) -> str:
    """Route after abuse detection."""
    if state.error:
        return END
    return "assess_risk"


def create_trust_relationship_mapper_graph() -> StateGraph:
    """Build the Trust Relationship Mapper workflow.

    Workflow:
        discover_trust_boundaries
            -> [no boundaries? -> report -> END]
            -> map_federation
            -> analyze_delegation_chains
            -> detect_trust_abuse
            -> assess_risk
            -> generate_report -> END
    """
    graph = StateGraph(TrustRelationshipMapperState)

    graph.add_node(
        "discover_trust_boundaries",
        traced_node(
            "trust_mapper.discover_trust_boundaries",
            _AGENT,
        )(discover_trust_boundaries),
    )
    graph.add_node(
        "map_federation",
        traced_node(
            "trust_mapper.map_federation",
            _AGENT,
        )(map_federation),
    )
    graph.add_node(
        "analyze_delegation_chains",
        traced_node(
            "trust_mapper.analyze_delegation_chains",
            _AGENT,
        )(analyze_delegation_chains),
    )
    graph.add_node(
        "detect_trust_abuse",
        traced_node(
            "trust_mapper.detect_trust_abuse",
            _AGENT,
        )(detect_trust_abuse),
    )
    graph.add_node(
        "assess_risk",
        traced_node(
            "trust_mapper.assess_risk",
            _AGENT,
        )(assess_risk),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            "trust_mapper.generate_report",
            _AGENT,
        )(generate_report),
    )

    graph.set_entry_point("discover_trust_boundaries")
    graph.add_conditional_edges(
        "discover_trust_boundaries",
        _has_boundaries,
        {
            "map_federation": "map_federation",
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge(
        "map_federation",
        "analyze_delegation_chains",
    )
    graph.add_edge(
        "analyze_delegation_chains",
        "detect_trust_abuse",
    )
    graph.add_conditional_edges(
        "detect_trust_abuse",
        _has_abuses,
        {
            "assess_risk": "assess_risk",
            END: END,
        },
    )
    graph.add_edge("assess_risk", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
