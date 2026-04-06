"""LangGraph workflow for Threat Scenario Runner."""

from __future__ import annotations

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import ThreatScenarioRunnerState
from .nodes import (
    evaluate_controls,
    execute_steps,
    generate_verdict,
    load_scenario,
    report,
    setup_environment,
)


def build_graph(toolkit: object = None):  # type: ignore[no-untyped-def]
    """Build the threat_scenario_runner agent graph (linear sequence)."""
    return build_linear_graph(
        ThreatScenarioRunnerState,
        [
            ("load_scenario", load_scenario),
            ("setup_environment", setup_environment),
            ("execute_steps", execute_steps),
            ("evaluate_controls", evaluate_controls),
            ("generate_verdict", generate_verdict),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_threat_scenario_runner_graph() -> StateGraph:
    """Factory to create the Threat Scenario graph."""
    return build_graph()
