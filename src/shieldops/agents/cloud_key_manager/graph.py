"""Cloud Key Manager Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CloudKeyManagerState
from .nodes import (
    assess_risk,
    audit_rotation,
    check_usage,
    discover_keys,
    enforce_policy,
    generate_report,
)
from .tools import CloudKeyManagerToolkit


def build_graph(
    toolkit: CloudKeyManagerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Key Manager graph.

    Flow:
        discover_keys -> audit_rotation
        -> check_usage -> assess_risk
        -> enforce_policy -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_keys(
            _to_dict(state),
            toolkit,
        )

    async def _audit(
        state: Any,
    ) -> dict[str, Any]:
        return await audit_rotation(
            _to_dict(state),
            toolkit,
        )

    async def _usage(
        state: Any,
    ) -> dict[str, Any]:
        return await check_usage(
            _to_dict(state),
            toolkit,
        )

    async def _risk(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_risk(
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

    graph = StateGraph(CloudKeyManagerState)
    graph.add_node("discover_keys", _discover)
    graph.add_node("audit_rotation", _audit)
    graph.add_node("check_usage", _usage)
    graph.add_node("assess_risk", _risk)
    graph.add_node("enforce_policy", _enforce)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_keys")
    graph.add_edge(
        "discover_keys",
        "audit_rotation",
    )
    graph.add_edge(
        "audit_rotation",
        "check_usage",
    )
    graph.add_edge(
        "check_usage",
        "assess_risk",
    )
    graph.add_edge(
        "assess_risk",
        "enforce_policy",
    )
    graph.add_edge(
        "enforce_policy",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_cloud_key_manager_graph(
    kms_client: Any | None = None,
    vault_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Key Manager graph."""
    toolkit = CloudKeyManagerToolkit(
        kms_client=kms_client,
        vault_client=vault_client,
    )
    return build_graph(toolkit)
