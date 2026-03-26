"""Supply Chain Scanner Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

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


def build_graph(
    toolkit: SupplyChainScannerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Supply Chain Scanner graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _inventory(
        state: Any,
    ) -> dict[str, Any]:
        return await inventory_ai_assets(_to_dict(state), toolkit)

    async def _scan_registries(
        state: Any,
    ) -> dict[str, Any]:
        return await scan_model_registries(_to_dict(state), toolkit)

    async def _scan_rag(
        state: Any,
    ) -> dict[str, Any]:
        return await scan_rag_sources(_to_dict(state), toolkit)

    async def _scan_templates(
        state: Any,
    ) -> dict[str, Any]:
        return await scan_prompt_templates(_to_dict(state), toolkit)

    async def _scan_tools(
        state: Any,
    ) -> dict[str, Any]:
        return await scan_tool_definitions(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(SupplyChainScannerState)
    graph.add_node("inventory_ai_assets", _inventory)
    graph.add_node("scan_model_registries", _scan_registries)
    graph.add_node("scan_rag_sources", _scan_rag)
    graph.add_node("scan_prompt_templates", _scan_templates)
    graph.add_node("scan_tool_definitions", _scan_tools)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("inventory_ai_assets")
    graph.add_edge(
        "inventory_ai_assets",
        "scan_model_registries",
    )
    graph.add_edge(
        "scan_model_registries",
        "scan_rag_sources",
    )
    graph.add_edge(
        "scan_rag_sources",
        "scan_prompt_templates",
    )
    graph.add_edge(
        "scan_prompt_templates",
        "scan_tool_definitions",
    )
    graph.add_edge(
        "scan_tool_definitions",
        "generate_report",
    )
    graph.add_edge("generate_report", END)

    return graph


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
