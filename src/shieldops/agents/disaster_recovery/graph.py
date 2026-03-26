"""LangGraph workflow definition for the Disaster Recovery Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.disaster_recovery.models import DisasterRecoveryState
from shieldops.agents.disaster_recovery.nodes import (
    assess_plans,
    identify_gaps,
    measure_rto_rpo,
    remediate,
    report,
    test_failover,
)
from shieldops.agents.tracing import traced_node


def should_remediate(state: DisasterRecoveryState) -> str:
    """Route to remediation if critical gaps exist, otherwise skip to report."""
    if state.error:
        return "report"
    if state.has_critical_gaps:
        return "remediate"
    return "report"


def create_disaster_recovery_graph() -> StateGraph[DisasterRecoveryState]:
    """Build the Disaster Recovery Agent LangGraph workflow.

    Workflow:
        assess_plans -> test_failover -> measure_rto_rpo -> identify_gaps
            -> [has_critical_gaps? -> remediate] -> report
    """
    graph = StateGraph(DisasterRecoveryState)

    _agent = "disaster_recovery"
    graph.add_node(
        "assess_plans",
        traced_node("disaster_recovery.assess_plans", _agent)(assess_plans),
    )
    graph.add_node(
        "test_failover",
        traced_node("disaster_recovery.test_failover", _agent)(test_failover),
    )
    graph.add_node(
        "measure_rto_rpo",
        traced_node("disaster_recovery.measure_rto_rpo", _agent)(measure_rto_rpo),
    )
    graph.add_node(
        "identify_gaps",
        traced_node("disaster_recovery.identify_gaps", _agent)(identify_gaps),
    )
    graph.add_node(
        "remediate",
        traced_node("disaster_recovery.remediate", _agent)(remediate),
    )
    graph.add_node(
        "report",
        traced_node("disaster_recovery.report", _agent)(report),
    )

    # Define edges
    graph.set_entry_point("assess_plans")
    graph.add_edge("assess_plans", "test_failover")
    graph.add_edge("test_failover", "measure_rto_rpo")
    graph.add_edge("measure_rto_rpo", "identify_gaps")
    graph.add_conditional_edges(
        "identify_gaps",
        should_remediate,
        {"remediate": "remediate", "report": "report"},
    )
    graph.add_edge("remediate", "report")
    graph.add_edge("report", END)

    return graph
