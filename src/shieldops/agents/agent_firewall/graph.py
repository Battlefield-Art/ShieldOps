"""Agent Behavioral Firewall — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import AgentFirewallState
from .nodes import (
    build_baseline,
    detect_anomalies,
    enforce_actions,
    evaluate_policies,
    generate_alerts,
    ingest_calls,
    report,
)
from .tools import AgentFirewallToolkit


def _has_violations(state: Any) -> str:
    """Route based on whether policy violations were found."""
    if hasattr(state, "policy_violations"):
        violations = state.policy_violations
    else:
        violations = state.get("policy_violations", [])
    if violations:
        return "enforce"
    return "report"


def build_graph(toolkit: AgentFirewallToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Agent Behavioral Firewall graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _ingest(state: Any) -> dict[str, Any]:
        return await ingest_calls(_to_dict(state), toolkit)

    async def _baseline(state: Any) -> dict[str, Any]:
        return await build_baseline(_to_dict(state), toolkit)

    async def _anomalies(state: Any) -> dict[str, Any]:
        return await detect_anomalies(_to_dict(state), toolkit)

    async def _policies(state: Any) -> dict[str, Any]:
        return await evaluate_policies(_to_dict(state), toolkit)

    async def _enforce(state: Any) -> dict[str, Any]:
        return await enforce_actions(_to_dict(state), toolkit)

    async def _alerts(state: Any) -> dict[str, Any]:
        return await generate_alerts(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(AgentFirewallState)
    graph.add_node("ingest_calls", _ingest)
    graph.add_node("build_baseline", _baseline)
    graph.add_node("detect_anomalies", _anomalies)
    graph.add_node("evaluate_policies", _policies)
    graph.add_node("enforce_actions", _enforce)
    graph.add_node("generate_alerts", _alerts)
    graph.add_node("report", _report)

    graph.set_entry_point("ingest_calls")
    graph.add_edge("ingest_calls", "build_baseline")
    graph.add_edge("build_baseline", "detect_anomalies")
    graph.add_edge("detect_anomalies", "evaluate_policies")
    graph.add_conditional_edges(
        "evaluate_policies",
        _has_violations,
        {"enforce": "enforce_actions", "report": "report"},
    )
    graph.add_edge("enforce_actions", "generate_alerts")
    graph.add_edge("generate_alerts", "report")
    graph.add_edge("report", END)

    return graph


def create_agent_firewall_graph(
    policy_engine: Any | None = None,
    event_store: Any | None = None,
    alert_sink: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Agent Behavioral Firewall graph with dependencies."""
    toolkit = AgentFirewallToolkit(
        policy_engine=policy_engine,
        event_store=event_store,
        alert_sink=alert_sink,
    )
    return build_graph(toolkit)
