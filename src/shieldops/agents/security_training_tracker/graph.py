"""LangGraph workflow definition for the Security
Training Tracker Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.security_training_tracker.models import (
    SecurityTrainingTrackerState,
)
from shieldops.agents.security_training_tracker.nodes import (
    assess_requirements,
    assign_remediation,
    generate_report,
    identify_gaps,
    measure_effectiveness,
    track_completion,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_training_tracker"


def _should_remediate(
    state: SecurityTrainingTrackerState,
) -> str:
    """Route after gap identification: remediate if gaps
    found or on error, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if state.gaps:
        return "assign_remediation"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Training Tracker LangGraph
    workflow.

    Workflow:
        assess_requirements -> track_completion
            -> measure_effectiveness -> identify_gaps
            -> [gaps? -> assign_remediation]
            -> generate_report -> END
    """
    graph = StateGraph(SecurityTrainingTrackerState)

    graph.add_node(
        "assess_requirements",
        traced_node(f"{_AGENT}.assess_requirements", _AGENT)(assess_requirements),
    )
    graph.add_node(
        "track_completion",
        traced_node(f"{_AGENT}.track_completion", _AGENT)(track_completion),
    )
    graph.add_node(
        "measure_effectiveness",
        traced_node(f"{_AGENT}.measure_effectiveness", _AGENT)(measure_effectiveness),
    )
    graph.add_node(
        "identify_gaps",
        traced_node(f"{_AGENT}.identify_gaps", _AGENT)(identify_gaps),
    )
    graph.add_node(
        "assign_remediation",
        traced_node(f"{_AGENT}.assign_remediation", _AGENT)(assign_remediation),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    # Edges
    graph.set_entry_point("assess_requirements")
    graph.add_edge("assess_requirements", "track_completion")
    graph.add_edge("track_completion", "measure_effectiveness")
    graph.add_edge("measure_effectiveness", "identify_gaps")
    graph.add_conditional_edges(
        "identify_gaps",
        _should_remediate,
        {
            "assign_remediation": "assign_remediation",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("assign_remediation", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_training_tracker_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Security Training Tracker
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
