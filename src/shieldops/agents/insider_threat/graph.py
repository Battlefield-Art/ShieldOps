"""Insider Threat Detection Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import InsiderThreatState
from .nodes import (
    assess_risk,
    build_behavioral_baseline,
    collect_user_signals,
    detect_deviations,
    generate_report,
    investigate,
)
from .tools import InsiderThreatToolkit


def _has_high_risk_users(state: Any) -> str:
    """Route based on whether high-risk users exist."""
    if hasattr(state, "high_risk_users"):
        users = state.high_risk_users
    else:
        users = state.get("high_risk_users", [])
    if users:
        return "investigate"
    return "report"


def build_graph(
    toolkit: InsiderThreatToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Insider Threat Detection graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_user_signals(_to_dict(state), toolkit)

    async def _baseline(
        state: Any,
    ) -> dict[str, Any]:
        return await build_behavioral_baseline(_to_dict(state), toolkit)

    async def _deviations(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_deviations(_to_dict(state), toolkit)

    async def _risk(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_risk(_to_dict(state), toolkit)

    async def _investigate(
        state: Any,
    ) -> dict[str, Any]:
        return await investigate(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(InsiderThreatState)
    graph.add_node("collect_user_signals", _collect)
    graph.add_node("build_behavioral_baseline", _baseline)
    graph.add_node("detect_deviations", _deviations)
    graph.add_node("assess_risk", _risk)
    graph.add_node("investigate", _investigate)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_user_signals")
    graph.add_edge(
        "collect_user_signals",
        "build_behavioral_baseline",
    )
    graph.add_edge(
        "build_behavioral_baseline",
        "detect_deviations",
    )
    graph.add_edge("detect_deviations", "assess_risk")
    graph.add_conditional_edges(
        "assess_risk",
        _has_high_risk_users,
        {
            "investigate": "investigate",
            "report": "report",
        },
    )
    graph.add_edge("investigate", "report")
    graph.add_edge("report", END)

    return graph


def create_insider_threat_graph(
    identity_provider: Any | None = None,
    hr_system: Any | None = None,
    dlp_engine: Any | None = None,
    code_repo_connector: Any | None = None,
    ai_tool_monitor: Any | None = None,
    access_log_store: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Insider Threat Detection graph."""
    toolkit = InsiderThreatToolkit(
        identity_provider=identity_provider,
        hr_system=hr_system,
        dlp_engine=dlp_engine,
        code_repo_connector=code_repo_connector,
        ai_tool_monitor=ai_tool_monitor,
        access_log_store=access_log_store,
    )
    return build_graph(toolkit)
