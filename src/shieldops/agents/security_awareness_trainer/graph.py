"""LangGraph workflow for the Security Awareness Trainer."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_awareness_trainer.models import (
    SecurityAwarenessTrainerState,
)
from shieldops.agents.security_awareness_trainer.nodes import (
    assess_baseline,
    deliver_training,
    design_campaign,
    generate_content,
    measure_effectiveness,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_awareness_trainer"


def _check_error(
    state: SecurityAwarenessTrainerState,
) -> str:
    """Route to report on error."""
    if state.error:
        return "report"
    return "next"


def create_security_awareness_trainer_graph() -> StateGraph[SecurityAwarenessTrainerState]:
    """Build the Security Awareness Trainer workflow."""
    graph = StateGraph(SecurityAwarenessTrainerState)

    graph.add_node(
        "assess_baseline",
        traced_node(
            "sat.assess_baseline",
            _AGENT,
        )(assess_baseline),
    )
    graph.add_node(
        "design_campaign",
        traced_node(
            "sat.design_campaign",
            _AGENT,
        )(design_campaign),
    )
    graph.add_node(
        "generate_content",
        traced_node(
            "sat.generate_content",
            _AGENT,
        )(generate_content),
    )
    graph.add_node(
        "deliver_training",
        traced_node(
            "sat.deliver_training",
            _AGENT,
        )(deliver_training),
    )
    graph.add_node(
        "measure_effectiveness",
        traced_node(
            "sat.measure_effectiveness",
            _AGENT,
        )(measure_effectiveness),
    )
    graph.add_node(
        "report",
        traced_node(
            "sat.report",
            _AGENT,
        )(report),
    )

    graph.set_entry_point("assess_baseline")

    graph.add_conditional_edges(
        "assess_baseline",
        _check_error,
        {
            "report": "report",
            "next": "design_campaign",
        },
    )
    graph.add_conditional_edges(
        "design_campaign",
        _check_error,
        {
            "report": "report",
            "next": "generate_content",
        },
    )
    graph.add_conditional_edges(
        "generate_content",
        _check_error,
        {
            "report": "report",
            "next": "deliver_training",
        },
    )
    graph.add_conditional_edges(
        "deliver_training",
        _check_error,
        {
            "report": "report",
            "next": "measure_effectiveness",
        },
    )
    graph.add_edge("measure_effectiveness", "report")
    graph.add_edge("report", END)

    return graph
