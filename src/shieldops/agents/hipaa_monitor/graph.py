"""HIPAA Monitor Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import HIPAAMonitorState
from .nodes import (
    assess_security_rule,
    audit_access,
    check_baas,
    check_minimum_necessary,
    generate_report,
)
from .tools import HIPAAMonitorToolkit


def _route_after_audit(state: Any) -> str:
    """Route based on error presence."""
    raw = state if isinstance(state, dict) else state.model_dump()
    if raw.get("error"):
        return "generate_report"
    return "minimum_necessary"


def create_hipaa_monitor_graph(
    toolkit: HIPAAMonitorToolkit | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the HIPAA Monitor agent graph."""
    if toolkit is None:
        toolkit = HIPAAMonitorToolkit()

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return state  # type: ignore[no-any-return]

    async def _audit(state: Any) -> dict[str, Any]:
        return await audit_access(_to_dict(state), toolkit)

    async def _min_nec(state: Any) -> dict[str, Any]:
        return await check_minimum_necessary(_to_dict(state), toolkit)

    async def _baas(state: Any) -> dict[str, Any]:
        return await check_baas(_to_dict(state), toolkit)

    async def _security(state: Any) -> dict[str, Any]:
        return await assess_security_rule(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(HIPAAMonitorState)
    graph.add_node("audit_access", _audit)
    graph.add_node("minimum_necessary", _min_nec)
    graph.add_node("check_baas", _baas)
    graph.add_node("security_rule", _security)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("audit_access")
    graph.add_conditional_edges(
        "audit_access",
        _route_after_audit,
        {
            "minimum_necessary": "minimum_necessary",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("minimum_necessary", "check_baas")
    graph.add_edge("check_baas", "security_rule")
    graph.add_edge("security_rule", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
