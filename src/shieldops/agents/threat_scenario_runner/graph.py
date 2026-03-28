"""LangGraph workflow for Threat Scenario Runner."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.threat_scenario_runner.models import (
    ThreatScenarioRunnerState,
)
from shieldops.agents.threat_scenario_runner.nodes import (
    evaluate_controls,
    execute_steps,
    generate_verdict,
    load_scenario,
    report,
    setup_environment,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def build_graph(
    toolkit: object | None = None,
) -> StateGraph:
    """Build the Threat Scenario Runner workflow.

    Workflow::

        load_scenario -> setup_environment
            -> execute_steps -> evaluate_controls
            -> generate_verdict -> report -> END
    """
    _a = "threat_scenario_runner"
    graph = StateGraph(ThreatScenarioRunnerState)

    graph.add_node(
        "load_scenario",
        traced_node(f"{_a}.load_scenario", _a)(load_scenario),
    )
    graph.add_node(
        "setup_environment",
        traced_node(f"{_a}.setup_environment", _a)(setup_environment),
    )
    graph.add_node(
        "execute_steps",
        traced_node(f"{_a}.execute_steps", _a)(execute_steps),
    )
    graph.add_node(
        "evaluate_controls",
        traced_node(f"{_a}.evaluate_controls", _a)(evaluate_controls),
    )
    graph.add_node(
        "generate_verdict",
        traced_node(f"{_a}.generate_verdict", _a)(generate_verdict),
    )
    graph.add_node(
        "report",
        traced_node(f"{_a}.report", _a)(report),
    )

    graph.set_entry_point("load_scenario")
    graph.add_edge("load_scenario", "setup_environment")
    graph.add_edge("setup_environment", "execute_steps")
    graph.add_edge("execute_steps", "evaluate_controls")
    graph.add_edge("evaluate_controls", "generate_verdict")
    graph.add_edge("generate_verdict", "report")
    graph.add_edge("report", END)

    return graph


def create_threat_scenario_runner_graph() -> StateGraph:
    """Factory to create the Threat Scenario graph."""
    return build_graph()
