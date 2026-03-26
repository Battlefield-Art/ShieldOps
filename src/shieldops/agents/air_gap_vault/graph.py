"""LangGraph workflow definition for the Air-Gap Vault Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.air_gap_vault.models import AirGapVaultState
from shieldops.agents.air_gap_vault.nodes import (
    check_integrity,
    detect_tampering,
    enforce_retention,
    generate_report,
    inventory_vault_assets,
    verify_isolation,
)
from shieldops.agents.tracing import traced_node


def route_after_isolation(state: AirGapVaultState) -> str:
    """Route based on isolation verification results.

    If isolation failed, skip to report with error.
    Otherwise proceed to integrity checking.
    """
    if state.error:
        return "generate_report"
    if not state.isolation_passed:
        return "generate_report"
    return "check_integrity"


def create_air_gap_vault_graph() -> StateGraph[AirGapVaultState]:
    """Build the Air-Gap Vault Agent LangGraph workflow.

    Workflow:
        inventory_vault_assets -> verify_isolation
            -> [conditional: check_integrity OR generate_report]
        check_integrity -> detect_tampering
            -> enforce_retention -> generate_report -> END
    """
    graph = StateGraph(AirGapVaultState)

    _agent = "air_gap_vault"

    graph.add_node(
        "inventory_vault_assets",
        traced_node("vault.inventory_assets", _agent)(inventory_vault_assets),
    )
    graph.add_node(
        "verify_isolation",
        traced_node("vault.verify_isolation", _agent)(verify_isolation),
    )
    graph.add_node(
        "check_integrity",
        traced_node("vault.check_integrity", _agent)(check_integrity),
    )
    graph.add_node(
        "detect_tampering",
        traced_node("vault.detect_tampering", _agent)(detect_tampering),
    )
    graph.add_node(
        "enforce_retention",
        traced_node("vault.enforce_retention", _agent)(enforce_retention),
    )
    graph.add_node(
        "generate_report",
        traced_node("vault.generate_report", _agent)(generate_report),
    )

    # Define edges
    graph.set_entry_point("inventory_vault_assets")
    graph.add_edge("inventory_vault_assets", "verify_isolation")
    graph.add_conditional_edges(
        "verify_isolation",
        route_after_isolation,
        {
            "check_integrity": "check_integrity",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("check_integrity", "detect_tampering")
    graph.add_edge("detect_tampering", "enforce_retention")
    graph.add_edge("enforce_retention", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
