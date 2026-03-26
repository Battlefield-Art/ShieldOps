"""LangGraph workflow definition for the Multi-Agent Security Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.multi_agent_security.models import MultiAgentSecurityState
from shieldops.agents.multi_agent_security.nodes import (
    detect_anomalies,
    discover_interactions,
    enforce_policies,
    generate_report,
    map_trust_chains,
    set_toolkit,
    verify_communications,
)
from shieldops.agents.multi_agent_security.tools import MultiAgentSecurityToolkit
from shieldops.agents.tracing import traced_node


def _should_enforce(state: MultiAgentSecurityState) -> str:
    """Route to enforcement if anomalies were detected, else skip to report."""
    if state.error:
        return "generate_report"
    if state.threats_detected:
        return "enforce_policies"
    return "generate_report"


def build_graph(toolkit: MultiAgentSecurityToolkit) -> StateGraph:
    """Build the Multi-Agent Security LangGraph workflow with the given toolkit.

    Workflow:
        discover_interactions -> map_trust_chains -> verify_communications
            -> detect_anomalies
            -> [threats? -> enforce_policies]
            -> generate_report -> END
    """
    set_toolkit(toolkit)
    graph = StateGraph(MultiAgentSecurityState)

    _agent = "multi_agent_security"
    graph.add_node(
        "discover_interactions",
        traced_node(f"{_agent}.discover_interactions", _agent)(discover_interactions),
    )
    graph.add_node(
        "map_trust_chains",
        traced_node(f"{_agent}.map_trust_chains", _agent)(map_trust_chains),
    )
    graph.add_node(
        "verify_communications",
        traced_node(f"{_agent}.verify_communications", _agent)(verify_communications),
    )
    graph.add_node(
        "detect_anomalies",
        traced_node(f"{_agent}.detect_anomalies", _agent)(detect_anomalies),
    )
    graph.add_node(
        "enforce_policies",
        traced_node(f"{_agent}.enforce_policies", _agent)(enforce_policies),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_agent}.generate_report", _agent)(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_interactions")
    graph.add_edge("discover_interactions", "map_trust_chains")
    graph.add_edge("map_trust_chains", "verify_communications")
    graph.add_edge("verify_communications", "detect_anomalies")
    graph.add_conditional_edges(
        "detect_anomalies",
        _should_enforce,
        {
            "enforce_policies": "enforce_policies",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("enforce_policies", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_multi_agent_security_graph(
    **clients: Any,
) -> StateGraph:
    """Factory: create the graph with optional injected clients.

    Accepted keyword arguments:
        identity_registry, policy_engine, message_bus, telemetry, repository
    """
    toolkit = MultiAgentSecurityToolkit(
        identity_registry=clients.get("identity_registry"),
        policy_engine=clients.get("policy_engine"),
        message_bus=clients.get("message_bus"),
        telemetry=clients.get("telemetry"),
        repository=clients.get("repository"),
    )
    return build_graph(toolkit)
