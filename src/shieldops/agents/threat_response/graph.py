"""Threat Response Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import ThreatResponseState
from .nodes import (
    classify_threat,
    execute_containment,
    execute_eradication,
    generate_report,
    select_playbook,
    verify_remediation,
)
from .tools import ThreatResponseToolkit


def build_graph(toolkit: ThreatResponseToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Threat Response agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _classify(state: Any) -> dict[str, Any]:
        return await classify_threat(_to_dict(state), toolkit)

    async def _playbook(state: Any) -> dict[str, Any]:
        return await select_playbook(_to_dict(state), toolkit)

    async def _contain(state: Any) -> dict[str, Any]:
        return await execute_containment(_to_dict(state), toolkit)

    async def _eradicate(state: Any) -> dict[str, Any]:
        return await execute_eradication(_to_dict(state), toolkit)

    async def _verify(state: Any) -> dict[str, Any]:
        return await verify_remediation(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(ThreatResponseState)
    graph.add_node("classify_threat", _classify)
    graph.add_node("select_playbook", _playbook)
    graph.add_node("execute_containment", _contain)
    graph.add_node("execute_eradication", _eradicate)
    graph.add_node("verify_remediation", _verify)
    graph.add_node("report", _report)

    graph.set_entry_point("classify_threat")
    graph.add_edge("classify_threat", "select_playbook")
    graph.add_edge("select_playbook", "execute_containment")
    graph.add_edge("execute_containment", "execute_eradication")
    graph.add_edge("execute_eradication", "verify_remediation")
    graph.add_edge("verify_remediation", "report")
    graph.add_edge("report", END)

    return graph


def create_threat_response_graph(
    soar_client: Any | None = None,
    edr_client: Any | None = None,
    firewall_client: Any | None = None,
    identity_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Threat Response agent graph with dependencies."""
    toolkit = ThreatResponseToolkit(
        soar_client=soar_client,
        edr_client=edr_client,
        firewall_client=firewall_client,
        identity_client=identity_client,
    )
    return build_graph(toolkit)
