"""LangGraph workflow definition for Data Security Posture."""

from langgraph.graph import END, StateGraph

from shieldops.agents.data_security_posture.models import (
    DataSecurityPostureState,
)
from shieldops.agents.data_security_posture.nodes import (
    apply_controls,
    assess_risks,
    classify_data,
    discover_data_stores,
    generate_report,
    validate_posture,
)
from shieldops.agents.tracing import traced_node

# ── Routing Functions ───────────────────────────────────


def should_classify(
    state: DataSecurityPostureState,
) -> str:
    """Route after discovery based on results."""
    if state.error:
        return "generate_report"
    if state.total_stores > 0:
        return "classify_data"
    return "generate_report"


def should_apply_controls(
    state: DataSecurityPostureState,
) -> str:
    """Route after risk assessment based on severity."""
    if state.high_risk_count > 0:
        return "apply_controls"
    return "generate_report"


# ── Graph Builder ───────────────────────────────────────


def create_data_security_posture_graph() -> StateGraph[DataSecurityPostureState]:
    """Build the Data Security Posture LangGraph workflow.

    Workflow:
        discover_data_stores
          -> [has_stores? -> classify_data]
          -> assess_risks
          -> [high_risk? -> apply_controls]
          -> validate_posture
          -> generate_report
    """
    graph = StateGraph(DataSecurityPostureState)

    _agent = "data_security_posture"
    graph.add_node(
        "discover_data_stores",
        traced_node(
            "dsp.discover_data_stores",
            _agent,
        )(discover_data_stores),
    )
    graph.add_node(
        "classify_data",
        traced_node(
            "dsp.classify_data",
            _agent,
        )(classify_data),
    )
    graph.add_node(
        "assess_risks",
        traced_node(
            "dsp.assess_risks",
            _agent,
        )(assess_risks),
    )
    graph.add_node(
        "apply_controls",
        traced_node(
            "dsp.apply_controls",
            _agent,
        )(apply_controls),
    )
    graph.add_node(
        "validate_posture",
        traced_node(
            "dsp.validate_posture",
            _agent,
        )(validate_posture),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            "dsp.generate_report",
            _agent,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("discover_data_stores")
    graph.add_conditional_edges(
        "discover_data_stores",
        should_classify,
        {
            "classify_data": "classify_data",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("classify_data", "assess_risks")
    graph.add_conditional_edges(
        "assess_risks",
        should_apply_controls,
        {
            "apply_controls": "apply_controls",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("apply_controls", "validate_posture")
    graph.add_edge("validate_posture", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
