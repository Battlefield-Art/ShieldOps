"""LangGraph workflow definition for Quantum Risk Assessor."""

from langgraph.graph import END, StateGraph

from shieldops.agents.quantum_risk_assessor.models import (
    QuantumRiskAssessorState,
)
from shieldops.agents.quantum_risk_assessor.nodes import (
    assess_vulnerability,
    inventory_algorithms,
    recommend_migration,
    report,
    scan_infrastructure,
    score_readiness,
)
from shieldops.agents.tracing import traced_node

# ── Routing Functions ───────────────────────────────────


def _check_error(state: QuantumRiskAssessorState) -> str:
    """Route to report if an error occurred."""
    if state.error:
        return "report"
    return "continue"


def _after_scan(state: QuantumRiskAssessorState) -> str:
    """Route after infrastructure scan."""
    if state.error:
        return "report"
    if state.crypto_assets:
        return "inventory_algorithms"
    return "report"


def _after_inventory(state: QuantumRiskAssessorState) -> str:
    """Route after algorithm inventory."""
    if state.error:
        return "report"
    if state.algorithm_inventory:
        return "assess_vulnerability"
    return "report"


def _after_assess(state: QuantumRiskAssessorState) -> str:
    """Route after vulnerability assessment."""
    if state.error:
        return "report"
    return "score_readiness"


def _after_readiness(state: QuantumRiskAssessorState) -> str:
    """Route after readiness scoring."""
    if state.error:
        return "report"
    if state.critical_asset_count > 0:
        return "recommend_migration"
    return "report"


# ── Graph Builder ───────────────────────────────────────


def create_quantum_risk_assessor_graph() -> StateGraph[QuantumRiskAssessorState]:
    """Build the Quantum Risk Assessor LangGraph workflow.

    Workflow:
        scan_infrastructure
          -> [has_assets? -> inventory_algorithms]
          -> [has_inventory? -> assess_vulnerability]
          -> score_readiness
          -> [critical? -> recommend_migration]
          -> report
    """
    graph = StateGraph(QuantumRiskAssessorState)

    _agent = "quantum_risk_assessor"
    graph.add_node(
        "scan_infrastructure",
        traced_node(
            "quantum_risk.scan_infrastructure",
            _agent,
        )(scan_infrastructure),
    )
    graph.add_node(
        "inventory_algorithms",
        traced_node(
            "quantum_risk.inventory_algorithms",
            _agent,
        )(inventory_algorithms),
    )
    graph.add_node(
        "assess_vulnerability",
        traced_node(
            "quantum_risk.assess_vulnerability",
            _agent,
        )(assess_vulnerability),
    )
    graph.add_node(
        "score_readiness",
        traced_node(
            "quantum_risk.score_readiness",
            _agent,
        )(score_readiness),
    )
    graph.add_node(
        "recommend_migration",
        traced_node(
            "quantum_risk.recommend_migration",
            _agent,
        )(recommend_migration),
    )
    graph.add_node(
        "report",
        traced_node(
            "quantum_risk.report",
            _agent,
        )(report),
    )

    # Define edges
    graph.set_entry_point("scan_infrastructure")
    graph.add_conditional_edges(
        "scan_infrastructure",
        _after_scan,
        {
            "inventory_algorithms": "inventory_algorithms",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "inventory_algorithms",
        _after_inventory,
        {
            "assess_vulnerability": "assess_vulnerability",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "assess_vulnerability",
        _after_assess,
        {
            "score_readiness": "score_readiness",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "score_readiness",
        _after_readiness,
        {
            "recommend_migration": "recommend_migration",
            "report": "report",
        },
    )
    graph.add_edge("recommend_migration", "report")
    graph.add_edge("report", END)

    return graph
