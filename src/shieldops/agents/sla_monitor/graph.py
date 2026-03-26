"""LangGraph workflow definition for the SLA Monitor Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.sla_monitor.models import SLAMonitorState
from shieldops.agents.sla_monitor.nodes import (
    alert,
    calculate_slos,
    collect_slis,
    detect_burn_rates,
    report,
    track_error_budgets,
)
from shieldops.agents.tracing import traced_node


def should_alert(state: SLAMonitorState) -> str:
    """Route to alerting if burn rate alerts were detected."""
    if state.error:
        return "report"
    if state.has_alerts:
        return "alert"
    return "report"


def create_sla_monitor_graph() -> StateGraph[SLAMonitorState]:
    """Build the SLA Monitor Agent LangGraph workflow.

    Workflow:
        collect_slis → calculate_slos → track_error_budgets
            → detect_burn_rates → [has_alerts? → alert] → report
    """
    graph = StateGraph(SLAMonitorState)

    _agent = "sla_monitor"
    graph.add_node(
        "collect_slis",
        traced_node("sla_monitor.collect_slis", _agent)(collect_slis),
    )
    graph.add_node(
        "calculate_slos",
        traced_node("sla_monitor.calculate_slos", _agent)(calculate_slos),
    )
    graph.add_node(
        "track_error_budgets",
        traced_node("sla_monitor.track_error_budgets", _agent)(track_error_budgets),
    )
    graph.add_node(
        "detect_burn_rates",
        traced_node("sla_monitor.detect_burn_rates", _agent)(detect_burn_rates),
    )
    graph.add_node(
        "alert",
        traced_node("sla_monitor.alert", _agent)(alert),
    )
    graph.add_node(
        "report",
        traced_node("sla_monitor.report", _agent)(report),
    )

    # Define edges
    graph.set_entry_point("collect_slis")
    graph.add_edge("collect_slis", "calculate_slos")
    graph.add_edge("calculate_slos", "track_error_budgets")
    graph.add_edge("track_error_budgets", "detect_burn_rates")
    graph.add_conditional_edges(
        "detect_burn_rates",
        should_alert,
        {"alert": "alert", "report": "report"},
    )
    graph.add_edge("alert", "report")
    graph.add_edge("report", END)

    return graph
