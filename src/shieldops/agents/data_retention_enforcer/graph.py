"""Data Retention Enforcer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

from .models import DataRetentionEnforcerState
from .nodes import (
    check_expiry,
    classify_retention,
    discover_data,
    enforce_deletion,
    report,
    verify_compliance,
)
from .tools import DataRetentionEnforcerToolkit

_AGENT = "data_retention_enforcer"


def _check_error(
    state: DataRetentionEnforcerState,
) -> str:
    if state.error:
        return "report"
    return "continue"


def build_graph(
    toolkit: DataRetentionEnforcerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Data Retention Enforcer graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_data(
            _to_dict(state),
            toolkit,
        )

    async def _classify(
        state: Any,
    ) -> dict[str, Any]:
        return await classify_retention(
            _to_dict(state),
            toolkit,
        )

    async def _expiry(
        state: Any,
    ) -> dict[str, Any]:
        return await check_expiry(
            _to_dict(state),
            toolkit,
        )

    async def _delete(
        state: Any,
    ) -> dict[str, Any]:
        return await enforce_deletion(
            _to_dict(state),
            toolkit,
        )

    async def _verify(
        state: Any,
    ) -> dict[str, Any]:
        return await verify_compliance(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(DataRetentionEnforcerState)
    graph.add_node(
        "discover_data",
        traced_node("dre.discover", _AGENT)(_discover),
    )
    graph.add_node(
        "classify_retention",
        traced_node("dre.classify", _AGENT)(_classify),
    )
    graph.add_node(
        "check_expiry",
        traced_node("dre.expiry", _AGENT)(_expiry),
    )
    graph.add_node(
        "enforce_deletion",
        traced_node("dre.delete", _AGENT)(_delete),
    )
    graph.add_node(
        "verify_compliance",
        traced_node("dre.verify", _AGENT)(_verify),
    )
    graph.add_node(
        "report",
        traced_node("dre.report", _AGENT)(_report),
    )

    graph.set_entry_point("discover_data")
    graph.add_edge("discover_data", "classify_retention")
    graph.add_edge("classify_retention", "check_expiry")
    graph.add_edge("check_expiry", "enforce_deletion")
    graph.add_edge(
        "enforce_deletion",
        "verify_compliance",
    )
    graph.add_edge("verify_compliance", "report")
    graph.add_edge("report", END)

    return graph


def create_data_retention_enforcer_graph(
    data_catalog: Any | None = None,
    deletion_api: Any | None = None,
    legal_hold_api: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Data Retention Enforcer graph."""
    toolkit = DataRetentionEnforcerToolkit(
        data_catalog=data_catalog,
        deletion_api=deletion_api,
        legal_hold_api=legal_hold_api,
    )
    return build_graph(toolkit)
