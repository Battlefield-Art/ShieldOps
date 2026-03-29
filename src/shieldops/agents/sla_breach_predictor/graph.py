"""SLA Breach Predictor Agent graph."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.sla_breach_predictor.models import SlaBreachPredictorState
from shieldops.agents.sla_breach_predictor.nodes import (
    alert,
    collect_tickets,
    compute_velocity,
    predict_breach,
    rank_risk,
    report,
)
from shieldops.agents.tracing import traced_node

_AGENT = "sla_breach_predictor"


def _check_error(state: SlaBreachPredictorState) -> str:
    return "report" if state.error else "next"


def create_sla_breach_predictor_graph() -> StateGraph:
    """Build the SLA Breach Predictor workflow."""
    graph = StateGraph(SlaBreachPredictorState)

    graph.add_node(
        "collect_tickets",
        traced_node(f"{_AGENT}.collect_tickets", _AGENT)(collect_tickets),
    )
    graph.add_node(
        "compute_velocity",
        traced_node(f"{_AGENT}.compute_velocity", _AGENT)(compute_velocity),
    )
    graph.add_node(
        "predict_breach",
        traced_node(f"{_AGENT}.predict_breach", _AGENT)(predict_breach),
    )
    graph.add_node(
        "rank_risk",
        traced_node(f"{_AGENT}.rank_risk", _AGENT)(rank_risk),
    )
    graph.add_node(
        "alert",
        traced_node(f"{_AGENT}.alert", _AGENT)(alert),
    )
    graph.add_node(
        "report",
        traced_node(f"{_AGENT}.report", _AGENT)(report),
    )

    graph.set_entry_point("collect_tickets")

    graph.add_conditional_edges(
        "collect_tickets",
        _check_error,
        {"next": "compute_velocity", "report": "report"},
    )
    graph.add_conditional_edges(
        "compute_velocity",
        _check_error,
        {"next": "predict_breach", "report": "report"},
    )
    graph.add_conditional_edges(
        "predict_breach",
        _check_error,
        {"next": "rank_risk", "report": "report"},
    )
    graph.add_conditional_edges(
        "rank_risk",
        _check_error,
        {"next": "alert", "report": "report"},
    )
    graph.add_edge("alert", "report")
    graph.add_edge("report", END)

    return graph
