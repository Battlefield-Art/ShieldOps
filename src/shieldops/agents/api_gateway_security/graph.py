"""API Gateway Security Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import APIGatewaySecurityState
from .nodes import (
    analyze_auth,
    detect_abuse,
    discover_apis,
    enforce_policies,
    generate_report,
    scan_endpoints,
)
from .tools import APIGatewaySecurityToolkit


def _needs_enforcement(state: Any) -> str:
    """Route based on whether issues require enforcement."""
    if hasattr(state, "auth_analyses"):
        auths = state.auth_analyses
        scans = state.endpoint_scans
        abuses = state.abuse_detections
    else:
        auths = state.get("auth_analyses", [])
        scans = state.get("endpoint_scans", [])
        abuses = state.get("abuse_detections", [])
    if auths or scans or abuses:
        return "enforce"
    return "report"


def build_graph(
    toolkit: APIGatewaySecurityToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the API Gateway Security agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_apis(
            _to_dict(state),
            toolkit,
        )

    async def _auth(state: Any) -> dict[str, Any]:
        return await analyze_auth(
            _to_dict(state),
            toolkit,
        )

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_endpoints(
            _to_dict(state),
            toolkit,
        )

    async def _abuse(state: Any) -> dict[str, Any]:
        return await detect_abuse(
            _to_dict(state),
            toolkit,
        )

    async def _enforce(state: Any) -> dict[str, Any]:
        return await enforce_policies(
            _to_dict(state),
            toolkit,
        )

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(APIGatewaySecurityState)
    graph.add_node("discover_apis", _discover)
    graph.add_node("analyze_auth", _auth)
    graph.add_node("scan_endpoints", _scan)
    graph.add_node("detect_abuse", _abuse)
    graph.add_node("enforce_policies", _enforce)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("discover_apis")
    graph.add_edge("discover_apis", "analyze_auth")
    graph.add_edge("analyze_auth", "scan_endpoints")
    graph.add_edge("scan_endpoints", "detect_abuse")
    graph.add_conditional_edges(
        "detect_abuse",
        _needs_enforcement,
        {
            "enforce": "enforce_policies",
            "report": "generate_report",
        },
    )
    graph.add_edge("enforce_policies", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_api_gateway_security_graph(
    gateway_client: Any | None = None,
    waf_client: Any | None = None,
    traffic_store: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the API Gateway Security graph with deps."""
    toolkit = APIGatewaySecurityToolkit(
        gateway_client=gateway_client,
        waf_client=waf_client,
        traffic_store=traffic_store,
    )
    return build_graph(toolkit)
