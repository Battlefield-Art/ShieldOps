"""Packet Inspector Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import PacketInspectorState
from .nodes import (
    analyze_payloads,
    capture_packets,
    detect_threats,
    generate_report,
    validate_tls,
)
from .tools import PacketInspectorToolkit


def _has_tls_traffic(state: Any) -> str:
    """Route: validate TLS only if TLS traffic present."""
    packets = state.packets if hasattr(state, "packets") else state.get("packets", [])

    for p in packets:
        port = p.get("dst_port", 0) if isinstance(p, dict) else p.dst_port
        if port in (443, 8443, 993, 995, 465):
            return "validate_tls"

    return "detect_threats"


def build_graph(
    toolkit: PacketInspectorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Packet Inspector graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _capture(
        state: Any,
    ) -> dict[str, Any]:
        return await capture_packets(_to_dict(state), toolkit)

    async def _payloads(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_payloads(_to_dict(state), toolkit)

    async def _tls(
        state: Any,
    ) -> dict[str, Any]:
        return await validate_tls(_to_dict(state), toolkit)

    async def _threats(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_threats(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(PacketInspectorState)
    graph.add_node("capture_packets", _capture)
    graph.add_node("analyze_payloads", _payloads)
    graph.add_node("validate_tls", _tls)
    graph.add_node("detect_threats", _threats)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("capture_packets")
    graph.add_edge("capture_packets", "analyze_payloads")
    graph.add_conditional_edges(
        "analyze_payloads",
        _has_tls_traffic,
        {
            "validate_tls": "validate_tls",
            "detect_threats": "detect_threats",
        },
    )
    graph.add_edge("validate_tls", "detect_threats")
    graph.add_edge("detect_threats", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_packet_inspector_graph(
    pcap_client: Any | None = None,
    tls_client: Any | None = None,
    threat_feed_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Packet Inspector graph."""
    toolkit = PacketInspectorToolkit(
        pcap_client=pcap_client,
        tls_client=tls_client,
        threat_feed_client=threat_feed_client,
    )
    return build_graph(toolkit)
