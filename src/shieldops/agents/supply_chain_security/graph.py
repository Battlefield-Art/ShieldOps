"""Supply Chain Security Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: SupplyChainSecurityToolkit):  # type: ignore[no-untyped-def]
    """Build the supply_chain_security agent graph (linear sequence)."""
    return build_linear_graph(
        SupplyChainSecurityState,
        [
            ("generate_sbom", generate_sbom),
            ("scan_dependencies", scan_dependencies),
            ("audit_cicd", audit_cicd),
            ("verify_signatures", verify_signatures),
            ("assess_risk", assess_risk),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


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
