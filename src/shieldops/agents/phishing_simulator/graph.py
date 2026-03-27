"""LangGraph workflow for the Phishing Simulator Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.phishing_simulator.models import (
    PhishingSimulatorState,
)
from shieldops.agents.phishing_simulator.nodes import (
    analyze_results,
    design_campaign,
    generate_report,
    select_targets,
    send_simulations,
    track_responses,
)
from shieldops.agents.phishing_simulator.tools import (
    PhishingSimulatorToolkit,
)
from shieldops.agents.tracing import traced_node

_AGENT = "phishing_simulator"


def _has_responses(
    state: PhishingSimulatorState,
) -> str:
    """Route based on response data."""
    if state.error:
        return "generate_report"
    if state.responses_tracked:
        return "analyze_results"
    return "generate_report"


def build_graph(
    toolkit: PhishingSimulatorToolkit,
) -> StateGraph:
    """Build the phishing simulator LangGraph workflow.

    Workflow:
        design_campaign -> select_targets
            -> send_simulations -> track_responses
            -> [responses? -> analyze_results]
            -> generate_report -> END
    """
    graph = StateGraph(PhishingSimulatorState)

    async def _design(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await design_campaign(state, toolkit)

    async def _targets(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await select_targets(state, toolkit)

    async def _send(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await send_simulations(state, toolkit)

    async def _track(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await track_responses(state, toolkit)

    async def _analyze(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await analyze_results(state, toolkit)

    async def _report(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await generate_report(state, toolkit)

    graph.add_node(
        "design_campaign",
        traced_node(f"{_AGENT}.design_campaign", _AGENT)(_design),
    )
    graph.add_node(
        "select_targets",
        traced_node(f"{_AGENT}.select_targets", _AGENT)(_targets),
    )
    graph.add_node(
        "send_simulations",
        traced_node(f"{_AGENT}.send_simulations", _AGENT)(_send),
    )
    graph.add_node(
        "track_responses",
        traced_node(f"{_AGENT}.track_responses", _AGENT)(_track),
    )
    graph.add_node(
        "analyze_results",
        traced_node(f"{_AGENT}.analyze_results", _AGENT)(_analyze),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(_report),
    )

    graph.set_entry_point("design_campaign")
    graph.add_edge("design_campaign", "select_targets")
    graph.add_edge("select_targets", "send_simulations")
    graph.add_edge("send_simulations", "track_responses")
    graph.add_conditional_edges(
        "track_responses",
        _has_responses,
        {
            "analyze_results": "analyze_results",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("analyze_results", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_phishing_simulator_graph(
    **clients: Any,
) -> StateGraph:
    """Factory to create a phishing simulator graph."""
    toolkit = PhishingSimulatorToolkit(
        email_client=clients.get("email_client"),
        hr_directory=clients.get("hr_directory"),
        policy_engine=clients.get("policy_engine"),
        repository=clients.get("repository"),
    )
    return build_graph(toolkit)
