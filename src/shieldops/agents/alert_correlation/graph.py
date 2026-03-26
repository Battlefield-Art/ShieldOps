"""LangGraph workflow definition for the Alert Correlation Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.alert_correlation.models import AlertCorrelationState
from shieldops.agents.alert_correlation.nodes import (
    build_kill_chains,
    collect_alerts,
    correlate_alerts,
    generate_report,
    normalize_alerts,
    prioritize_incidents,
)
from shieldops.agents.tracing import traced_node


def has_alerts(state: AlertCorrelationState) -> str:
    """Route based on whether alerts were collected."""
    if state.error:
        return END
    if not state.raw_alerts:
        return "generate_report"
    return "normalize_alerts"


def has_clusters(state: AlertCorrelationState) -> str:
    """Route based on whether correlation clusters were formed."""
    if state.error:
        return END
    if not state.clusters:
        return "generate_report"
    return "build_kill_chains"


def create_alert_correlation_graph() -> StateGraph:
    """Build the Alert Correlation Agent LangGraph workflow.

    Workflow:
        collect_alerts → [no alerts? → generate_report → END]
            → normalize_alerts → correlate_alerts
            → [no clusters? → generate_report → END]
            → build_kill_chains → prioritize_incidents
            → generate_report → END
    """
    graph = StateGraph(AlertCorrelationState)

    _agent = "alert_correlation"
    graph.add_node(
        "collect_alerts",
        traced_node("alert_correlation.collect_alerts", _agent)(collect_alerts),
    )
    graph.add_node(
        "normalize_alerts",
        traced_node("alert_correlation.normalize_alerts", _agent)(normalize_alerts),
    )
    graph.add_node(
        "correlate_alerts",
        traced_node("alert_correlation.correlate_alerts", _agent)(correlate_alerts),
    )
    graph.add_node(
        "build_kill_chains",
        traced_node("alert_correlation.build_kill_chains", _agent)(build_kill_chains),
    )
    graph.add_node(
        "prioritize_incidents",
        traced_node("alert_correlation.prioritize_incidents", _agent)(prioritize_incidents),
    )
    graph.add_node(
        "generate_report",
        traced_node("alert_correlation.generate_report", _agent)(generate_report),
    )

    # Define edges
    graph.set_entry_point("collect_alerts")
    graph.add_conditional_edges(
        "collect_alerts",
        has_alerts,
        {
            "normalize_alerts": "normalize_alerts",
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge("normalize_alerts", "correlate_alerts")
    graph.add_conditional_edges(
        "correlate_alerts",
        has_clusters,
        {
            "build_kill_chains": "build_kill_chains",
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge("build_kill_chains", "prioritize_incidents")
    graph.add_edge("prioritize_incidents", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
