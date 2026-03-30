"""LangGraph workflow for the Cloud Secret Vault Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.cloud_secret_vault.models import (
    CloudSecretVaultState,
)
from shieldops.agents.cloud_secret_vault.nodes import (
    assess_risk,
    audit_rotation,
    check_exposure,
    discover_secrets,
    generate_report,
    remediate_exposure,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cloud_secret_vault"


def _should_audit(
    state: CloudSecretVaultState,
) -> str:
    """Route after discovery based on results."""
    if state.error:
        return "generate_report"
    if state.discovered_secrets:
        return "audit_rotation"
    return "generate_report"


def _should_remediate(
    state: CloudSecretVaultState,
) -> str:
    """Route after risk assessment based on score."""
    if state.max_risk_score > 40.0:
        return "remediate_exposure"
    return "generate_report"


def create_cloud_secret_vault_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Secret Vault LangGraph.

    Workflow:
        discover_secrets
          -> [has_secrets?] -> audit_rotation
          -> check_exposure
          -> assess_risk
          -> [high_risk?] -> remediate_exposure
          -> generate_report
    """
    graph = StateGraph(CloudSecretVaultState)

    graph.add_node(
        "discover_secrets",
        traced_node(
            f"{_AGENT}.discover_secrets",
            _AGENT,
        )(discover_secrets),
    )
    graph.add_node(
        "audit_rotation",
        traced_node(
            f"{_AGENT}.audit_rotation",
            _AGENT,
        )(audit_rotation),
    )
    graph.add_node(
        "check_exposure",
        traced_node(
            f"{_AGENT}.check_exposure",
            _AGENT,
        )(check_exposure),
    )
    graph.add_node(
        "assess_risk",
        traced_node(
            f"{_AGENT}.assess_risk",
            _AGENT,
        )(assess_risk),
    )
    graph.add_node(
        "remediate_exposure",
        traced_node(
            f"{_AGENT}.remediate_exposure",
            _AGENT,
        )(remediate_exposure),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_secrets")
    graph.add_conditional_edges(
        "discover_secrets",
        _should_audit,
        {
            "audit_rotation": "audit_rotation",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("audit_rotation", "check_exposure")
    graph.add_edge("check_exposure", "assess_risk")
    graph.add_conditional_edges(
        "assess_risk",
        _should_remediate,
        {
            "remediate_exposure": "remediate_exposure",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("remediate_exposure", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
