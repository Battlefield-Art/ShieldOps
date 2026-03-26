"""Certificate Manager Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CertificateManagerState
from .nodes import (
    check_expiry,
    discover_certs,
    execute_rotation,
    generate_report,
    plan_rotation,
    validate_chains,
)
from .tools import CertificateManagerToolkit


def build_graph(toolkit: CertificateManagerToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Certificate Manager agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_certs(_to_dict(state), toolkit)

    async def _check(state: Any) -> dict[str, Any]:
        return await check_expiry(_to_dict(state), toolkit)

    async def _validate(state: Any) -> dict[str, Any]:
        return await validate_chains(_to_dict(state), toolkit)

    async def _plan(state: Any) -> dict[str, Any]:
        return await plan_rotation(_to_dict(state), toolkit)

    async def _execute(state: Any) -> dict[str, Any]:
        return await execute_rotation(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(CertificateManagerState)
    graph.add_node("discover_certs", _discover)
    graph.add_node("check_expiry", _check)
    graph.add_node("validate_chains", _validate)
    graph.add_node("plan_rotation", _plan)
    graph.add_node("execute_rotation", _execute)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_certs")
    graph.add_edge("discover_certs", "check_expiry")
    graph.add_edge("check_expiry", "validate_chains")
    graph.add_edge("validate_chains", "plan_rotation")
    graph.add_edge("plan_rotation", "execute_rotation")
    graph.add_edge("execute_rotation", "report")
    graph.add_edge("report", END)

    return graph


def create_certificate_manager_graph(
    cert_store: Any | None = None,
    acme_client: Any | None = None,
    dns_client: Any | None = None,
    notification_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Certificate Manager agent graph with dependencies."""
    toolkit = CertificateManagerToolkit(
        cert_store=cert_store,
        acme_client=acme_client,
        dns_client=dns_client,
        notification_client=notification_client,
    )
    return build_graph(toolkit)
