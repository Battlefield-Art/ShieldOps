"""AI Runtime Defense Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import AIRuntimeDefenseState
from .nodes import (
    detect_exfiltration,
    detect_model_abuse,
    execute_response,
    generate_policies,
    generate_report,
    scan_prompts,
    scan_supply_chain,
)
from .tools import AIRuntimeDefenseToolkit


def _has_findings(state: Any) -> str:
    """Route based on whether any security findings were detected."""
    if hasattr(state, "model_dump"):
        d = state.model_dump()
    elif isinstance(state, dict):
        d = state
    else:
        d = dict(state)

    total = (
        len(d.get("prompt_injection_findings", []))
        + len(d.get("exfiltration_attempts", []))
        + len(d.get("model_abuse_incidents", []))
        + len(d.get("supply_chain_risks", []))
    )

    return "generate_policies" if total > 0 else "generate_report"


def build_graph(toolkit: AIRuntimeDefenseToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the AI Runtime Defense agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _scan_prompts(state: Any) -> dict[str, Any]:
        return await scan_prompts(_to_dict(state), toolkit)

    async def _detect_exfiltration(state: Any) -> dict[str, Any]:
        return await detect_exfiltration(_to_dict(state), toolkit)

    async def _detect_model_abuse(state: Any) -> dict[str, Any]:
        return await detect_model_abuse(_to_dict(state), toolkit)

    async def _scan_supply_chain(state: Any) -> dict[str, Any]:
        return await scan_supply_chain(_to_dict(state), toolkit)

    async def _generate_policies(state: Any) -> dict[str, Any]:
        return await generate_policies(_to_dict(state), toolkit)

    async def _execute_response(state: Any) -> dict[str, Any]:
        return await execute_response(_to_dict(state), toolkit)

    async def _generate_report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(AIRuntimeDefenseState)

    # Add all nodes
    graph.add_node("scan_prompts", _scan_prompts)
    graph.add_node("detect_exfiltration", _detect_exfiltration)
    graph.add_node("detect_model_abuse", _detect_model_abuse)
    graph.add_node("scan_supply_chain", _scan_supply_chain)
    graph.add_node("generate_policies", _generate_policies)
    graph.add_node("execute_response", _execute_response)
    graph.add_node("generate_report", _generate_report)

    # Entry: sequential scanning pipeline
    graph.set_entry_point("scan_prompts")
    graph.add_edge("scan_prompts", "detect_exfiltration")
    graph.add_edge("detect_exfiltration", "detect_model_abuse")
    graph.add_edge("detect_model_abuse", "scan_supply_chain")

    # Conditional: if findings exist, generate policies and respond; otherwise report
    graph.add_conditional_edges(
        "scan_supply_chain",
        _has_findings,
        {
            "generate_policies": "generate_policies",
            "generate_report": "generate_report",
        },
    )

    # If policies generated, execute response then report
    graph.add_edge("generate_policies", "execute_response")
    graph.add_edge("execute_response", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_ai_runtime_defense_graph(
    firewall_client: Any | None = None,
    credential_manager: Any | None = None,
    threat_intel: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the AI Runtime Defense agent graph with dependencies."""
    toolkit = AIRuntimeDefenseToolkit(
        firewall_client=firewall_client,
        credential_manager=credential_manager,
        threat_intel=threat_intel,
    )
    return build_graph(toolkit)
