"""SaaS Security Posture Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SaaSSecurityPostureState
from .nodes import (
    assess_risk,
    audit_config,
    check_sharing,
    discover_apps,
    generate_report,
    remediate,
)
from .tools import SaaSSecurityPostureToolkit


def build_graph(
    toolkit: SaaSSecurityPostureToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the SaaS Security Posture graph.

    Flow:
        discover_apps -> audit_config
        -> check_sharing -> assess_risk
        -> remediate -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_apps(
            _to_dict(state),
            toolkit,
        )

    async def _audit(
        state: Any,
    ) -> dict[str, Any]:
        return await audit_config(
            _to_dict(state),
            toolkit,
        )

    async def _sharing(
        state: Any,
    ) -> dict[str, Any]:
        return await check_sharing(
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

    async def _remediate(
        state: Any,
    ) -> dict[str, Any]:
        return await remediate(
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

    graph = StateGraph(SaaSSecurityPostureState)
    graph.add_node("discover_apps", _discover)
    graph.add_node("audit_config", _audit)
    graph.add_node("check_sharing", _sharing)
    graph.add_node("assess_risk", _risk)
    graph.add_node("remediate", _remediate)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_apps")
    graph.add_edge(
        "discover_apps",
        "audit_config",
    )
    graph.add_edge(
        "audit_config",
        "check_sharing",
    )
    graph.add_edge(
        "check_sharing",
        "assess_risk",
    )
    graph.add_edge(
        "assess_risk",
        "remediate",
    )
    graph.add_edge(
        "remediate",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_saas_security_posture_graph(
    saas_api: Any | None = None,
    identity_provider: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the SaaS Security Posture graph."""
    toolkit = SaaSSecurityPostureToolkit(
        saas_api=saas_api,
        identity_provider=identity_provider,
    )
    return build_graph(toolkit)
