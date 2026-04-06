"""Supply Chain Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SupplyChainScannerState
from .nodes import (
    generate_report,
    inventory_ai_assets,
    scan_model_registries,
    scan_prompt_templates,
    scan_rag_sources,
    scan_tool_definitions,
)
from .tools import SupplyChainScannerToolkit


def build_graph(toolkit: SupplyChainScannerToolkit):  # type: ignore[no-untyped-def]
    """Build the supply_chain_scanner agent graph (linear sequence)."""
    return build_linear_graph(
        SupplyChainScannerState,
        [
            ("inventory_ai_assets", inventory_ai_assets),
            ("scan_model_registries", scan_model_registries),
            ("scan_rag_sources", scan_rag_sources),
            ("scan_prompt_templates", scan_prompt_templates),
            ("scan_tool_definitions", scan_tool_definitions),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_supply_chain_scanner_graph(
    model_registry_client: Any | None = None,
    rag_client: Any | None = None,
    template_store: Any | None = None,
    tool_registry: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Supply Chain Scanner graph."""
    toolkit = SupplyChainScannerToolkit(
        model_registry_client=model_registry_client,
        rag_client=rag_client,
        template_store=template_store,
        tool_registry=tool_registry,
    )
    return build_graph(toolkit)
