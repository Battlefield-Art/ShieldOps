"""Secret Rotation Manager Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecretRotationManagerState
from .nodes import (
    assess_rotation,
    execute_rotation,
    generate_report,
    inventory_secrets,
    plan_rotation,
    verify_health,
)
from .tools import SecretRotationManagerToolkit


def build_graph(
    toolkit: SecretRotationManagerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Secret Rotation Manager graph.

    Flow:
        inventory_secrets -> assess_rotation
        -> plan_rotation -> execute_rotation
        -> verify_health -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _inventory(
        state: Any,
    ) -> dict[str, Any]:
        return await inventory_secrets(
            _to_dict(state),
            toolkit,
        )

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_rotation(
            _to_dict(state),
            toolkit,
        )

    async def _plan(
        state: Any,
    ) -> dict[str, Any]:
        return await plan_rotation(
            _to_dict(state),
            toolkit,
        )

    async def _execute(
        state: Any,
    ) -> dict[str, Any]:
        return await execute_rotation(
            _to_dict(state),
            toolkit,
        )

    async def _verify(
        state: Any,
    ) -> dict[str, Any]:
        return await verify_health(
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

    graph = StateGraph(SecretRotationManagerState)
    graph.add_node("inventory_secrets", _inventory)
    graph.add_node("assess_rotation", _assess)
    graph.add_node("plan_rotation", _plan)
    graph.add_node("execute_rotation", _execute)
    graph.add_node("verify_health", _verify)
    graph.add_node("report", _report)

    graph.set_entry_point("inventory_secrets")
    graph.add_edge(
        "inventory_secrets",
        "assess_rotation",
    )
    graph.add_edge(
        "assess_rotation",
        "plan_rotation",
    )
    graph.add_edge(
        "plan_rotation",
        "execute_rotation",
    )
    graph.add_edge(
        "execute_rotation",
        "verify_health",
    )
    graph.add_edge("verify_health", "report")
    graph.add_edge("report", END)

    return graph


def create_secret_rotation_manager_graph(
    vault_client: Any | None = None,
    cloud_provider: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Secret Rotation Manager graph."""
    toolkit = SecretRotationManagerToolkit(
        vault_client=vault_client,
        cloud_provider=cloud_provider,
    )
    return build_graph(toolkit)
