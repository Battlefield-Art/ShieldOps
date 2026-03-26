"""LangGraph workflow for the Managed Threat Hunting Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.managed_threat_hunting.models import (
    ManagedThreatHuntingState,
)
from shieldops.agents.managed_threat_hunting.nodes import (
    analyze_findings,
    collect_telemetry,
    escalate_threats,
    execute_hunts,
    generate_hunt_leads,
    report,
)
from shieldops.agents.tracing import traced_node


def should_escalate(
    state: ManagedThreatHuntingState,
) -> str:
    """Route to escalation if threats were found."""
    if state.error:
        return "report"
    if state.threats_found > 0:
        return "escalate_threats"
    return "report"


def create_managed_threat_hunting_graph() -> StateGraph[ManagedThreatHuntingState]:
    """Build the Managed Threat Hunting LangGraph.

    Workflow:
        generate_hunt_leads -> collect_telemetry
            -> execute_hunts -> analyze_findings
            -> [threats? -> escalate_threats]
            -> report -> END
    """
    graph = StateGraph(ManagedThreatHuntingState)

    _agent = "managed_threat_hunting"
    graph.add_node(
        "generate_hunt_leads",
        traced_node(
            "managed_threat_hunting.generate_leads",
            _agent,
        )(generate_hunt_leads),
    )
    graph.add_node(
        "collect_telemetry",
        traced_node(
            "managed_threat_hunting.collect_telemetry",
            _agent,
        )(collect_telemetry),
    )
    graph.add_node(
        "execute_hunts",
        traced_node(
            "managed_threat_hunting.execute_hunts",
            _agent,
        )(execute_hunts),
    )
    graph.add_node(
        "analyze_findings",
        traced_node(
            "managed_threat_hunting.analyze_findings",
            _agent,
        )(analyze_findings),
    )
    graph.add_node(
        "escalate_threats",
        traced_node(
            "managed_threat_hunting.escalate_threats",
            _agent,
        )(escalate_threats),
    )
    graph.add_node(
        "report",
        traced_node(
            "managed_threat_hunting.report",
            _agent,
        )(report),
    )

    # Linear pipeline with conditional escalation
    graph.set_entry_point("generate_hunt_leads")
    graph.add_edge("generate_hunt_leads", "collect_telemetry")
    graph.add_edge("collect_telemetry", "execute_hunts")
    graph.add_edge("execute_hunts", "analyze_findings")
    graph.add_conditional_edges(
        "analyze_findings",
        should_escalate,
        {
            "escalate_threats": "escalate_threats",
            "report": "report",
        },
    )
    graph.add_edge("escalate_threats", "report")
    graph.add_edge("report", END)

    return graph
