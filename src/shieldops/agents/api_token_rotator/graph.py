"""API Token Rotator Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import APITokenRotatorState
from .nodes import (
    assess_risk,
    audit_age,
    discover_tokens,
    generate_report,
    rotate_tokens,
)
from .tools import APITokenRotatorToolkit


def build_graph(
    toolkit: APITokenRotatorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the API Token Rotator graph.

    Flow:
        discover_tokens -> audit_age -> assess_risk
        -> rotate -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_tokens(
            _to_dict(state),
            toolkit,
        )

    async def _audit(
        state: Any,
    ) -> dict[str, Any]:
        return await audit_age(
            _to_dict(state),
            toolkit,
        )

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_risk(
            _to_dict(state),
            toolkit,
        )

    async def _rotate(
        state: Any,
    ) -> dict[str, Any]:
        return await rotate_tokens(
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

    graph = StateGraph(APITokenRotatorState)
    graph.add_node("discover_tokens", _discover)
    graph.add_node("audit_age", _audit)
    graph.add_node("assess_risk", _assess)
    graph.add_node("rotate", _rotate)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_tokens")
    graph.add_edge(
        "discover_tokens",
        "audit_age",
    )
    graph.add_edge(
        "audit_age",
        "assess_risk",
    )
    graph.add_edge(
        "assess_risk",
        "rotate",
    )
    graph.add_edge(
        "rotate",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_api_token_rotator_graph(
    credential_store: Any | None = None,
    secret_manager: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the API Token Rotator graph."""
    toolkit = APITokenRotatorToolkit(
        credential_store=credential_store,
        secret_manager=secret_manager,
    )
    return build_graph(toolkit)
