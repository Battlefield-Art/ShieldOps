"""Crypto Agility Manager Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CryptoAgilityManagerState
from .nodes import (
    assess_agility,
    discover_algorithms,
    execute_migration,
    plan_migration,
    report,
    test_compatibility,
)
from .tools import CryptoAgilityManagerToolkit


def _route_after_discover(state: Any) -> str:
    """Route after discovery — skip to report on error."""
    err = state.error if hasattr(state, "error") else state.get("error", "")
    return "report" if err else "assess_agility"


def build_graph(toolkit: CryptoAgilityManagerToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Crypto Agility Manager agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_algorithms(_to_dict(state), toolkit)

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_agility(_to_dict(state), toolkit)

    async def _plan(state: Any) -> dict[str, Any]:
        return await plan_migration(_to_dict(state), toolkit)

    async def _test(state: Any) -> dict[str, Any]:
        return await test_compatibility(_to_dict(state), toolkit)

    async def _execute(state: Any) -> dict[str, Any]:
        return await execute_migration(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(CryptoAgilityManagerState)
    graph.add_node("discover_algorithms", _discover)
    graph.add_node("assess_agility", _assess)
    graph.add_node("plan_migration", _plan)
    graph.add_node("test_compatibility", _test)
    graph.add_node("execute_migration", _execute)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_algorithms")
    graph.add_conditional_edges(
        "discover_algorithms",
        _route_after_discover,
        {"assess_agility": "assess_agility", "report": "report"},
    )
    graph.add_edge("assess_agility", "plan_migration")
    graph.add_edge("plan_migration", "test_compatibility")
    graph.add_edge("test_compatibility", "execute_migration")
    graph.add_edge("execute_migration", "report")
    graph.add_edge("report", END)

    return graph


def create_crypto_agility_manager_graph(
    crypto_store: Any | None = None,
    pqc_test_client: Any | None = None,
    config_client: Any | None = None,
    notification_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Crypto Agility Manager agent graph with dependencies."""
    toolkit = CryptoAgilityManagerToolkit(
        crypto_store=crypto_store,
        pqc_test_client=pqc_test_client,
        config_client=config_client,
        notification_client=notification_client,
    )
    return build_graph(toolkit)
