"""DNS Security Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DNSSecurityState
from .nodes import (
    collect_dns,
    detect_dga,
    detect_tunneling,
    detect_typosquatting,
    generate_report,
    respond_to_threats,
)
from .tools import DNSSecurityToolkit


def build_graph(toolkit: DNSSecurityToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the DNS Security agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(state: Any) -> dict[str, Any]:
        return await collect_dns(_to_dict(state), toolkit)

    async def _tunneling(state: Any) -> dict[str, Any]:
        return await detect_tunneling(_to_dict(state), toolkit)

    async def _dga(state: Any) -> dict[str, Any]:
        return await detect_dga(_to_dict(state), toolkit)

    async def _typosquatting(state: Any) -> dict[str, Any]:
        return await detect_typosquatting(_to_dict(state), toolkit)

    async def _respond(state: Any) -> dict[str, Any]:
        return await respond_to_threats(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(DNSSecurityState)
    graph.add_node("collect_dns", _collect)
    graph.add_node("detect_tunneling", _tunneling)
    graph.add_node("detect_dga", _dga)
    graph.add_node("detect_typosquatting", _typosquatting)
    graph.add_node("respond", _respond)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_dns")
    graph.add_edge("collect_dns", "detect_tunneling")
    graph.add_edge("detect_tunneling", "detect_dga")
    graph.add_edge("detect_dga", "detect_typosquatting")
    graph.add_edge("detect_typosquatting", "respond")
    graph.add_edge("respond", "report")
    graph.add_edge("report", END)

    return graph


def create_dns_security_graph(
    dns_log_client: Any | None = None,
    threat_intel_client: Any | None = None,
    firewall_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the DNS Security agent graph with dependencies."""
    toolkit = DNSSecurityToolkit(
        dns_log_client=dns_log_client,
        threat_intel_client=threat_intel_client,
        firewall_client=firewall_client,
    )
    return build_graph(toolkit)
