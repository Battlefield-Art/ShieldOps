"""DNS Firewall Controller Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DNSFirewallControllerState
from .nodes import (
    analyze_domains,
    check_reputation,
    detect_tunneling,
    enforce_policy,
    generate_report,
    ingest_queries,
)
from .tools import DNSFirewallControllerToolkit


def build_graph(
    toolkit: DNSFirewallControllerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the DNS Firewall Controller graph.

    Flow:
        ingest_queries -> analyze_domains
        -> check_reputation -> detect_tunneling
        -> enforce_policy -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _ingest(
        state: Any,
    ) -> dict[str, Any]:
        return await ingest_queries(
            _to_dict(state),
            toolkit,
        )

    async def _analyze(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_domains(
            _to_dict(state),
            toolkit,
        )

    async def _reputation(
        state: Any,
    ) -> dict[str, Any]:
        return await check_reputation(
            _to_dict(state),
            toolkit,
        )

    async def _tunneling(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_tunneling(
            _to_dict(state),
            toolkit,
        )

    async def _enforce(
        state: Any,
    ) -> dict[str, Any]:
        return await enforce_policy(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(DNSFirewallControllerState)
    graph.add_node("ingest_queries", _ingest)
    graph.add_node("analyze_domains", _analyze)
    graph.add_node("check_reputation", _reputation)
    graph.add_node("detect_tunneling", _tunneling)
    graph.add_node("enforce_policy", _enforce)
    graph.add_node("report", _report)

    graph.set_entry_point("ingest_queries")
    graph.add_edge(
        "ingest_queries",
        "analyze_domains",
    )
    graph.add_edge(
        "analyze_domains",
        "check_reputation",
    )
    graph.add_edge(
        "check_reputation",
        "detect_tunneling",
    )
    graph.add_edge(
        "detect_tunneling",
        "enforce_policy",
    )
    graph.add_edge(
        "enforce_policy",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_dns_firewall_controller_graph(
    dns_source: Any | None = None,
    reputation_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the DNS Firewall Controller graph."""
    toolkit = DNSFirewallControllerToolkit(
        dns_source=dns_source,
        reputation_api=reputation_api,
    )
    return build_graph(toolkit)
