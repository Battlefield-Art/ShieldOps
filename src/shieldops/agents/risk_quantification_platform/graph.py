"""LangGraph workflow definition for the Risk
Quantification Platform Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.risk_quantification_platform.models import (
    RiskQuantificationState,
)
from shieldops.agents.risk_quantification_platform.nodes import (
    assess_threats,
    calculate_risk,
    generate_report,
    identify_assets,
    model_loss,
    prioritize,
)
from shieldops.agents.tracing import traced_node

_AGENT = "risk_quantification_platform"


def _should_prioritize(
    state: RiskQuantificationState,
) -> str:
    """Route after risk calculation: prioritize if
    scores exist, otherwise skip to report."""
    if state.error:
        return "generate_report"
    if len(state.risk_scores) > 0:
        return "prioritize"
    return "generate_report"


def build_graph(
    toolkit: Any = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Risk Quantification Platform workflow.

    Workflow:
        identify_assets -> assess_threats -> model_loss
            -> calculate_risk -> [scores? -> prioritize]
            -> generate_report -> END
    """
    graph = StateGraph(RiskQuantificationState)

    graph.add_node(
        "identify_assets",
        traced_node(f"{_AGENT}.identify_assets", _AGENT)(identify_assets),
    )
    graph.add_node(
        "assess_threats",
        traced_node(f"{_AGENT}.assess_threats", _AGENT)(assess_threats),
    )
    graph.add_node(
        "model_loss",
        traced_node(f"{_AGENT}.model_loss", _AGENT)(model_loss),
    )
    graph.add_node(
        "calculate_risk",
        traced_node(f"{_AGENT}.calculate_risk", _AGENT)(calculate_risk),
    )
    graph.add_node(
        "prioritize",
        traced_node(f"{_AGENT}.prioritize", _AGENT)(prioritize),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("identify_assets")
    graph.add_edge("identify_assets", "assess_threats")
    graph.add_edge("assess_threats", "model_loss")
    graph.add_edge("model_loss", "calculate_risk")
    graph.add_conditional_edges(
        "calculate_risk",
        _should_prioritize,
        {
            "prioritize": "prioritize",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("prioritize", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_risk_quantification_platform_graph(
    **clients: Any,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory to create a Risk Quantification Platform
    graph with optional dependency injection."""
    return build_graph(toolkit=clients.get("toolkit"))
