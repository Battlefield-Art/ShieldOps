"""LangGraph workflow for the Attack Replay Simulator."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.attack_replay_simulator.models import (
    AttackReplaySimulatorState,
)
from shieldops.agents.attack_replay_simulator.nodes import (
    capture_telemetry,
    configure_sandbox,
    evaluate_detection,
    execute_replay,
    generate_report,
    select_techniques,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()

_AGENT = "attack_replay_simulator"


def _check_error(
    state: AttackReplaySimulatorState,
) -> str:
    """Route to report on error, otherwise continue."""
    if state.error:
        return "generate_report"
    return "next"


def create_attack_replay_simulator_graph() -> (
    StateGraph  # type: ignore[type-arg]
):
    """Build the Attack Replay Simulator LangGraph workflow.

    Workflow:
        select_techniques
        -> configure_sandbox
        -> execute_replay
        -> capture_telemetry
        -> evaluate_detection
        -> generate_report
        -> END
    """
    graph = StateGraph(AttackReplaySimulatorState)

    # Add nodes with OTEL tracing
    graph.add_node(
        "select_techniques",
        traced_node(
            f"{_AGENT}.select_techniques",
            _AGENT,
        )(select_techniques),
    )
    graph.add_node(
        "configure_sandbox",
        traced_node(
            f"{_AGENT}.configure_sandbox",
            _AGENT,
        )(configure_sandbox),
    )
    graph.add_node(
        "execute_replay",
        traced_node(
            f"{_AGENT}.execute_replay",
            _AGENT,
        )(execute_replay),
    )
    graph.add_node(
        "capture_telemetry",
        traced_node(
            f"{_AGENT}.capture_telemetry",
            _AGENT,
        )(capture_telemetry),
    )
    graph.add_node(
        "evaluate_detection",
        traced_node(
            f"{_AGENT}.evaluate_detection",
            _AGENT,
        )(evaluate_detection),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("select_techniques")
    graph.add_conditional_edges(
        "select_techniques",
        _check_error,
        {
            "next": "configure_sandbox",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "configure_sandbox",
        _check_error,
        {
            "next": "execute_replay",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "execute_replay",
        _check_error,
        {
            "next": "capture_telemetry",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "capture_telemetry",
        _check_error,
        {
            "next": "evaluate_detection",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("evaluate_detection", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
