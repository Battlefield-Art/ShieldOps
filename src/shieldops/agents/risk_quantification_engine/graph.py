"""LangGraph workflow for the Risk Quantification Engine."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.risk_quantification_engine.models import (
    RiskQuantificationEngineState,
)
from shieldops.agents.risk_quantification_engine.nodes import (
    calculate_exposure,
    estimate_loss,
    identify_assets,
    model_threats,
    prioritize_risks,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "risk_quantification_engine"


def _check_error(
    state: RiskQuantificationEngineState,
) -> str:
    """Route to report on error."""
    if state.error:
        return "report"
    return "next"


def create_risk_quantification_engine_graph() -> StateGraph[RiskQuantificationEngineState]:
    """Build the Risk Quantification Engine workflow."""
    graph = StateGraph(RiskQuantificationEngineState)

    graph.add_node(
        "identify_assets",
        traced_node(
            "rqe.identify_assets",
            _AGENT,
        )(identify_assets),
    )
    graph.add_node(
        "model_threats",
        traced_node(
            "rqe.model_threats",
            _AGENT,
        )(model_threats),
    )
    graph.add_node(
        "calculate_exposure",
        traced_node(
            "rqe.calculate_exposure",
            _AGENT,
        )(calculate_exposure),
    )
    graph.add_node(
        "estimate_loss",
        traced_node(
            "rqe.estimate_loss",
            _AGENT,
        )(estimate_loss),
    )
    graph.add_node(
        "prioritize_risks",
        traced_node(
            "rqe.prioritize_risks",
            _AGENT,
        )(prioritize_risks),
    )
    graph.add_node(
        "report",
        traced_node(
            "rqe.report",
            _AGENT,
        )(report),
    )

    graph.set_entry_point("identify_assets")

    graph.add_conditional_edges(
        "identify_assets",
        _check_error,
        {
            "report": "report",
            "next": "model_threats",
        },
    )
    graph.add_conditional_edges(
        "model_threats",
        _check_error,
        {
            "report": "report",
            "next": "calculate_exposure",
        },
    )
    graph.add_conditional_edges(
        "calculate_exposure",
        _check_error,
        {
            "report": "report",
            "next": "estimate_loss",
        },
    )
    graph.add_conditional_edges(
        "estimate_loss",
        _check_error,
        {
            "report": "report",
            "next": "prioritize_risks",
        },
    )
    graph.add_edge("prioritize_risks", "report")
    graph.add_edge("report", END)

    return graph
