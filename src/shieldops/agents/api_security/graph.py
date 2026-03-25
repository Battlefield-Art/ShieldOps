"""API Security Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import APISecurityState
from .nodes import (
    analyze_traffic,
    detect_abuse,
    detect_vulnerabilities,
    discover_endpoints,
    enforce_policies,
    generate_report,
)
from .tools import APISecurityToolkit


def _needs_enforcement(state: Any) -> str:
    """Route based on whether vulnerabilities or abuse were found."""
    if hasattr(state, "vulnerabilities"):
        vulns = state.vulnerabilities
        abuse = state.abuse_incidents
    else:
        vulns = state.get("vulnerabilities", [])
        abuse = state.get("abuse_incidents", [])
    if vulns or abuse:
        return "enforce"
    return "report"


def build_graph(toolkit: APISecurityToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the API Security agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_endpoints(_to_dict(state), toolkit)

    async def _traffic(state: Any) -> dict[str, Any]:
        return await analyze_traffic(_to_dict(state), toolkit)

    async def _vulns(state: Any) -> dict[str, Any]:
        return await detect_vulnerabilities(_to_dict(state), toolkit)

    async def _abuse(state: Any) -> dict[str, Any]:
        return await detect_abuse(_to_dict(state), toolkit)

    async def _enforce(state: Any) -> dict[str, Any]:
        return await enforce_policies(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(APISecurityState)
    graph.add_node("discover_endpoints", _discover)
    graph.add_node("analyze_traffic", _traffic)
    graph.add_node("detect_vulnerabilities", _vulns)
    graph.add_node("detect_abuse", _abuse)
    graph.add_node("enforce_policies", _enforce)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("discover_endpoints")
    graph.add_edge("discover_endpoints", "analyze_traffic")
    graph.add_edge("analyze_traffic", "detect_vulnerabilities")
    graph.add_edge("detect_vulnerabilities", "detect_abuse")
    graph.add_conditional_edges(
        "detect_abuse",
        _needs_enforcement,
        {"enforce": "enforce_policies", "report": "generate_report"},
    )
    graph.add_edge("enforce_policies", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_api_security_graph(
    api_gateway: Any | None = None,
    waf_client: Any | None = None,
    traffic_store: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the API Security graph with dependencies."""
    toolkit = APISecurityToolkit(
        api_gateway=api_gateway,
        waf_client=waf_client,
        traffic_store=traffic_store,
    )
    return build_graph(toolkit)
