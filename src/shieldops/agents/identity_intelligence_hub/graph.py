"""LangGraph workflow definition for Identity Intelligence Hub."""

from langgraph.graph import END, StateGraph

from shieldops.agents.identity_intelligence_hub.models import (
    IdentityIntelligenceHubState,
)
from shieldops.agents.identity_intelligence_hub.nodes import (
    assess_risk,
    collect_identity_signals,
    correlate_identities,
    detect_threats,
    generate_report,
    recommend_actions,
)
from shieldops.agents.tracing import traced_node

# ── Routing Functions ───────────────────────────────────


def should_correlate(
    state: IdentityIntelligenceHubState,
) -> str:
    """Route after collection based on results."""
    if state.error:
        return "generate_report"
    if state.total_signals > 0:
        return "correlate_identities"
    return "generate_report"


def should_recommend(
    state: IdentityIntelligenceHubState,
) -> str:
    """Route after risk assessment based on severity."""
    if state.high_risk_identities > 0:
        return "recommend_actions"
    return "generate_report"


# ── Graph Builder ───────────────────────────────────────


def create_identity_intelligence_hub_graph() -> StateGraph[IdentityIntelligenceHubState]:
    """Build the Identity Intelligence Hub workflow.

    Workflow:
        collect_identity_signals
          -> [has_signals? -> correlate_identities]
          -> detect_threats
          -> assess_risk
          -> [high_risk? -> recommend_actions]
          -> generate_report
    """
    graph = StateGraph(IdentityIntelligenceHubState)

    _agent = "identity_intelligence_hub"
    graph.add_node(
        "collect_identity_signals",
        traced_node(
            "iih.collect_identity_signals",
            _agent,
        )(collect_identity_signals),
    )
    graph.add_node(
        "correlate_identities",
        traced_node(
            "iih.correlate_identities",
            _agent,
        )(correlate_identities),
    )
    graph.add_node(
        "detect_threats",
        traced_node(
            "iih.detect_threats",
            _agent,
        )(detect_threats),
    )
    graph.add_node(
        "assess_risk",
        traced_node(
            "iih.assess_risk",
            _agent,
        )(assess_risk),
    )
    graph.add_node(
        "recommend_actions",
        traced_node(
            "iih.recommend_actions",
            _agent,
        )(recommend_actions),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            "iih.generate_report",
            _agent,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("collect_identity_signals")
    graph.add_conditional_edges(
        "collect_identity_signals",
        should_correlate,
        {
            "correlate_identities": ("correlate_identities"),
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("correlate_identities", "detect_threats")
    graph.add_edge("detect_threats", "assess_risk")
    graph.add_conditional_edges(
        "assess_risk",
        should_recommend,
        {
            "recommend_actions": "recommend_actions",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("recommend_actions", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
