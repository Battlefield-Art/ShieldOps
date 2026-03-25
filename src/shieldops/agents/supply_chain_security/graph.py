"""Supply Chain Security Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SupplyChainSecurityState
from .nodes import (
    assess_risk,
    audit_cicd,
    generate_report,
    generate_sbom,
    scan_dependencies,
    verify_signatures,
)
from .tools import SupplyChainSecurityToolkit


def build_graph(
    toolkit: SupplyChainSecurityToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Supply Chain Security graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _generate_sbom(state: Any) -> dict[str, Any]:
        return await generate_sbom(_to_dict(state), toolkit)

    async def _scan_dependencies(state: Any) -> dict[str, Any]:
        return await scan_dependencies(_to_dict(state), toolkit)

    async def _audit_cicd(state: Any) -> dict[str, Any]:
        return await audit_cicd(_to_dict(state), toolkit)

    async def _verify_signatures(state: Any) -> dict[str, Any]:
        return await verify_signatures(_to_dict(state), toolkit)

    async def _assess_risk(state: Any) -> dict[str, Any]:
        return await assess_risk(_to_dict(state), toolkit)

    async def _generate_report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(SupplyChainSecurityState)
    graph.add_node("generate_sbom", _generate_sbom)
    graph.add_node("scan_dependencies", _scan_dependencies)
    graph.add_node("audit_cicd", _audit_cicd)
    graph.add_node("verify_signatures", _verify_signatures)
    graph.add_node("assess_risk", _assess_risk)
    graph.add_node("generate_report", _generate_report)

    graph.set_entry_point("generate_sbom")
    graph.add_edge("generate_sbom", "scan_dependencies")
    graph.add_edge("scan_dependencies", "audit_cicd")
    graph.add_edge("audit_cicd", "verify_signatures")
    graph.add_edge("verify_signatures", "assess_risk")
    graph.add_edge("assess_risk", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_supply_chain_security_graph(
    git_client: Any | None = None,
    registry_client: Any | None = None,
    ci_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Supply Chain Security graph with dependencies."""
    toolkit = SupplyChainSecurityToolkit(
        git_client=git_client,
        registry_client=registry_client,
        ci_client=ci_client,
    )
    return build_graph(toolkit)
