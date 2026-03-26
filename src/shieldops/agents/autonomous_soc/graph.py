"""LangGraph workflow definition for the Autonomous SOC Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.autonomous_soc.models import (
    AutonomousSOCState,
)
from shieldops.agents.autonomous_soc.nodes import (
    auto_triage,
    correlate_incidents,
    ingest_events,
    measure_outcomes,
    ml_detect_anomalies,
    orchestrate_response,
    report,
)
from shieldops.agents.tracing import traced_node


def has_anomalies(
    state: AutonomousSOCState,
) -> str:
    """Route based on whether anomalies were detected."""
    if state.anomalies_detected > 0:
        return "correlate_incidents"
    return "measure_outcomes"


def has_actionable_incidents(
    state: AutonomousSOCState,
) -> str:
    """Route based on whether there are incidents to triage."""
    if state.incidents_created > 0:
        return "auto_triage"
    return "measure_outcomes"


def should_orchestrate(
    state: AutonomousSOCState,
) -> str:
    """Route based on auto-triage results."""
    if state.auto_triaged > 0:
        return "orchestrate_response"
    return "measure_outcomes"


def create_autonomous_soc_graph() -> StateGraph[AutonomousSOCState]:
    """Build the Autonomous SOC Agent LangGraph workflow.

    Workflow:
        ingest_events -> ml_detect_anomalies
            -> [anomalies?]
                yes -> correlate_incidents
                    -> [incidents?]
                        yes -> auto_triage
                            -> [auto-triaged?]
                                yes -> orchestrate_response
                                    -> measure_outcomes
                                    -> report -> END
                                no -> measure_outcomes
                                    -> report -> END
                        no -> measure_outcomes
                            -> report -> END
                no -> measure_outcomes
                    -> report -> END
    """
    graph = StateGraph(AutonomousSOCState)

    _agent = "autonomous_soc"
    graph.add_node(
        "ingest_events",
        traced_node(
            "autonomous_soc.ingest_events",
            _agent,
        )(ingest_events),
    )
    graph.add_node(
        "ml_detect_anomalies",
        traced_node(
            "autonomous_soc.ml_detect_anomalies",
            _agent,
        )(ml_detect_anomalies),
    )
    graph.add_node(
        "correlate_incidents",
        traced_node(
            "autonomous_soc.correlate_incidents",
            _agent,
        )(correlate_incidents),
    )
    graph.add_node(
        "auto_triage",
        traced_node(
            "autonomous_soc.auto_triage",
            _agent,
        )(auto_triage),
    )
    graph.add_node(
        "orchestrate_response",
        traced_node(
            "autonomous_soc.orchestrate_response",
            _agent,
        )(orchestrate_response),
    )
    graph.add_node(
        "measure_outcomes",
        traced_node(
            "autonomous_soc.measure_outcomes",
            _agent,
        )(measure_outcomes),
    )
    graph.add_node(
        "report",
        traced_node(
            "autonomous_soc.report",
            _agent,
        )(report),
    )

    # Define edges
    graph.set_entry_point("ingest_events")
    graph.add_edge(
        "ingest_events",
        "ml_detect_anomalies",
    )
    graph.add_conditional_edges(
        "ml_detect_anomalies",
        has_anomalies,
        {
            "correlate_incidents": ("correlate_incidents"),
            "measure_outcomes": "measure_outcomes",
        },
    )
    graph.add_conditional_edges(
        "correlate_incidents",
        has_actionable_incidents,
        {
            "auto_triage": "auto_triage",
            "measure_outcomes": "measure_outcomes",
        },
    )
    graph.add_conditional_edges(
        "auto_triage",
        should_orchestrate,
        {
            "orchestrate_response": ("orchestrate_response"),
            "measure_outcomes": "measure_outcomes",
        },
    )
    graph.add_edge(
        "orchestrate_response",
        "measure_outcomes",
    )
    graph.add_edge(
        "measure_outcomes",
        "report",
    )
    graph.add_edge("report", END)

    return graph
