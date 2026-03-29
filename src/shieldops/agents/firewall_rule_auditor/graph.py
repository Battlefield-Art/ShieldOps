"""Firewall Rule Auditor Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import FirewallAuditState
from .nodes import (
    check_compliance,
    classify_risks,
    collect_rules,
    detect_violations,
    generate_report,
    recommend_fixes,
)
from .tools import FirewallAuditToolkit


def build_graph(
    toolkit: FirewallAuditToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Firewall Rule Auditor agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(state: Any) -> dict[str, Any]:
        return await collect_rules(_to_dict(state), toolkit)

    async def _detect(state: Any) -> dict[str, Any]:
        return await detect_violations(_to_dict(state), toolkit)

    async def _classify(state: Any) -> dict[str, Any]:
        return await classify_risks(_to_dict(state), toolkit)

    async def _compliance(state: Any) -> dict[str, Any]:
        return await check_compliance(_to_dict(state), toolkit)

    async def _recommend(state: Any) -> dict[str, Any]:
        return await recommend_fixes(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(FirewallAuditState)

    # Add nodes
    graph.add_node("collect_rules", _collect)
    graph.add_node("detect_violations", _detect)
    graph.add_node("classify_risks", _classify)
    graph.add_node("check_compliance", _compliance)
    graph.add_node("recommend_fixes", _recommend)
    graph.add_node("generate_report", _report)

    # Linear flow
    graph.set_entry_point("collect_rules")
    graph.add_edge("collect_rules", "detect_violations")
    graph.add_edge("detect_violations", "classify_risks")
    graph.add_edge("classify_risks", "check_compliance")
    graph.add_edge("check_compliance", "recommend_fixes")
    graph.add_edge("recommend_fixes", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_firewall_rule_auditor_graph(
    cloud_clients: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Firewall Rule Auditor agent graph with dependencies."""
    toolkit = FirewallAuditToolkit(
        cloud_clients=cloud_clients,
    )
    return build_graph(toolkit)
