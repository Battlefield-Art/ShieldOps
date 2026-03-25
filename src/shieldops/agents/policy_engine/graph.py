"""Policy Engine Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import PolicyEngineState
from .nodes import (
    collect_requirements,
    detect_drift,
    generate_policies,
    generate_report,
    reconcile,
    validate_coverage,
)
from .tools import PolicyEngineToolkit


def _should_reconcile(state: Any) -> str:
    """Route to reconcile if drifts were found, otherwise skip to report."""
    if isinstance(state, dict):
        drifts = state.get("policy_drifts", [])
    else:
        drifts = getattr(state, "policy_drifts", [])
    return "reconcile" if drifts else "generate_report"


def build_graph(
    toolkit: PolicyEngineToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Policy Engine agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect_requirements(state: Any) -> dict[str, Any]:
        return await collect_requirements(_to_dict(state), toolkit)

    async def _generate_policies(state: Any) -> dict[str, Any]:
        return await generate_policies(_to_dict(state), toolkit)

    async def _validate_coverage(state: Any) -> dict[str, Any]:
        return await validate_coverage(_to_dict(state), toolkit)

    async def _detect_drift(state: Any) -> dict[str, Any]:
        return await detect_drift(_to_dict(state), toolkit)

    async def _reconcile(state: Any) -> dict[str, Any]:
        return await reconcile(_to_dict(state), toolkit)

    async def _generate_report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(PolicyEngineState)
    graph.add_node("collect_requirements", _collect_requirements)
    graph.add_node("generate_policies", _generate_policies)
    graph.add_node("validate_coverage", _validate_coverage)
    graph.add_node("detect_drift", _detect_drift)
    graph.add_node("reconcile", _reconcile)
    graph.add_node("generate_report", _generate_report)

    graph.set_entry_point("collect_requirements")
    graph.add_edge("collect_requirements", "generate_policies")
    graph.add_edge("generate_policies", "validate_coverage")
    graph.add_edge("validate_coverage", "detect_drift")
    graph.add_conditional_edges(
        "detect_drift",
        _should_reconcile,
        {"reconcile": "reconcile", "generate_report": "generate_report"},
    )
    graph.add_edge("reconcile", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_policy_engine_graph(
    opa_client: Any | None = None,
    policy_store: Any | None = None,
    compliance_registry: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Policy Engine agent graph with dependencies."""
    toolkit = PolicyEngineToolkit(
        opa_client=opa_client,
        policy_store=policy_store,
        compliance_registry=compliance_registry,
    )
    return build_graph(toolkit)
