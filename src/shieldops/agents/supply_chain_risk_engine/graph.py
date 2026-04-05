"""LangGraph workflow for the Supply Chain Risk Engine."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.supply_chain_risk_engine.models import (
    SupplyChainRiskEngineState,
)
from shieldops.agents.supply_chain_risk_engine.nodes import (
    assess_risk,
    generate_report,
    inventory_dependencies,
    map_blast_radius,
    recommend_mitigations,
    scan_vulnerabilities,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()

_AGENT = "supply_chain_risk_engine"


def _check_error(
    state: SupplyChainRiskEngineState,
) -> str:
    """Route to report on error, otherwise continue."""
    if state.error:
        return "generate_report"
    return "next"


def should_recommend(
    state: SupplyChainRiskEngineState,
) -> str:
    """Route: recommend mitigations if risks found."""
    if state.error:
        return "generate_report"
    if state.risk_assessments:
        return "recommend_mitigations"
    return "generate_report"


def create_supply_chain_risk_engine_graph() -> (
    StateGraph  # type: ignore[type-arg]
):
    """Build the Supply Chain Risk Engine LangGraph workflow.

    Workflow:
        inventory_dependencies
        -> scan_vulnerabilities
        -> assess_risk
        -> map_blast_radius
        -> [risks? -> recommend_mitigations]
        -> generate_report
        -> END
    """
    graph = StateGraph(SupplyChainRiskEngineState)

    # Add nodes with OTEL tracing
    graph.add_node(
        "inventory_dependencies",
        traced_node(
            f"{_AGENT}.inventory_dependencies",
            _AGENT,
        )(inventory_dependencies),
    )
    graph.add_node(
        "scan_vulnerabilities",
        traced_node(
            f"{_AGENT}.scan_vulnerabilities",
            _AGENT,
        )(scan_vulnerabilities),
    )
    graph.add_node(
        "assess_risk",
        traced_node(
            f"{_AGENT}.assess_risk",
            _AGENT,
        )(assess_risk),
    )
    graph.add_node(
        "map_blast_radius",
        traced_node(
            f"{_AGENT}.map_blast_radius",
            _AGENT,
        )(map_blast_radius),
    )
    graph.add_node(
        "recommend_mitigations",
        traced_node(
            f"{_AGENT}.recommend_mitigations",
            _AGENT,
        )(recommend_mitigations),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("inventory_dependencies")
    graph.add_conditional_edges(
        "inventory_dependencies",
        _check_error,
        {
            "next": "scan_vulnerabilities",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "scan_vulnerabilities",
        _check_error,
        {
            "next": "assess_risk",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("assess_risk", "map_blast_radius")
    graph.add_conditional_edges(
        "map_blast_radius",
        should_recommend,
        {
            "recommend_mitigations": "recommend_mitigations",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("recommend_mitigations", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
