"""Certificate Lifecycle Manager Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CertificateLifecycleManagerState
from .nodes import (
    check_expiry,
    discover_certs,
    execute_renewal,
    generate_report,
    plan_renewal,
    validate_config,
)
from .tools import CertificateLifecycleManagerToolkit


def build_graph(
    toolkit: CertificateLifecycleManagerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Certificate Lifecycle Manager agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_certs(_to_dict(state), toolkit)

    async def _check_expiry(
        state: Any,
    ) -> dict[str, Any]:
        return await check_expiry(_to_dict(state), toolkit)

    async def _validate_config(
        state: Any,
    ) -> dict[str, Any]:
        return await validate_config(_to_dict(state), toolkit)

    async def _plan_renewal(
        state: Any,
    ) -> dict[str, Any]:
        return await plan_renewal(_to_dict(state), toolkit)

    async def _execute_renewal(
        state: Any,
    ) -> dict[str, Any]:
        return await execute_renewal(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(CertificateLifecycleManagerState)
    graph.add_node("discover_certs", _discover)
    graph.add_node("check_expiry", _check_expiry)
    graph.add_node("validate_config", _validate_config)
    graph.add_node("plan_renewal", _plan_renewal)
    graph.add_node("execute_renewal", _execute_renewal)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_certs")
    graph.add_edge("discover_certs", "check_expiry")
    graph.add_edge("check_expiry", "validate_config")
    graph.add_edge("validate_config", "plan_renewal")
    graph.add_edge("plan_renewal", "execute_renewal")
    graph.add_edge("execute_renewal", "report")
    graph.add_edge("report", END)

    return graph


def create_certificate_lifecycle_manager_graph(
    acme_client: Any | None = None,
    scanner_client: Any | None = None,
    vault_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Certificate Lifecycle Manager graph."""
    toolkit = CertificateLifecycleManagerToolkit(
        acme_client=acme_client,
        scanner_client=scanner_client,
        vault_client=vault_client,
    )
    return build_graph(toolkit)
