"""LangGraph workflow for the Agent Trust Broker."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.agent_trust_broker.models import (
    AgentTrustBrokerState,
)
from shieldops.agents.agent_trust_broker.nodes import (
    establish_trust,
    generate_report,
    monitor_behavior,
    register_agents,
    revoke_compromised,
    validate_identity,
)
from shieldops.agents.tracing import traced_node

_AGENT = "agent_trust_broker"


def _should_establish(
    state: AgentTrustBrokerState,
) -> str:
    if state.error:
        return "generate_report"
    if state.validations:
        return "establish_trust"
    return "generate_report"


def _should_revoke(
    state: AgentTrustBrokerState,
) -> str:
    if state.behavior_records:
        return "revoke_compromised"
    return "generate_report"


def create_agent_trust_broker_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Agent Trust Broker LangGraph.

    Workflow:
        register_agents -> validate_identity
          -> [has_validations?] -> establish_trust
          -> monitor_behavior
          -> [has_records?] -> revoke_compromised
          -> generate_report
    """
    graph = StateGraph(AgentTrustBrokerState)

    graph.add_node(
        "register_agents",
        traced_node(f"{_AGENT}.register_agents", _AGENT)(
            register_agents,
        ),
    )
    graph.add_node(
        "validate_identity",
        traced_node(f"{_AGENT}.validate_identity", _AGENT)(
            validate_identity,
        ),
    )
    graph.add_node(
        "establish_trust",
        traced_node(f"{_AGENT}.establish_trust", _AGENT)(
            establish_trust,
        ),
    )
    graph.add_node(
        "monitor_behavior",
        traced_node(f"{_AGENT}.monitor_behavior", _AGENT)(
            monitor_behavior,
        ),
    )
    graph.add_node(
        "revoke_compromised",
        traced_node(f"{_AGENT}.revoke_compromised", _AGENT)(
            revoke_compromised,
        ),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(
            generate_report,
        ),
    )

    graph.set_entry_point("register_agents")
    graph.add_edge("register_agents", "validate_identity")
    graph.add_conditional_edges(
        "validate_identity",
        _should_establish,
        {
            "establish_trust": "establish_trust",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("establish_trust", "monitor_behavior")
    graph.add_conditional_edges(
        "monitor_behavior",
        _should_revoke,
        {
            "revoke_compromised": "revoke_compromised",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("revoke_compromised", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
