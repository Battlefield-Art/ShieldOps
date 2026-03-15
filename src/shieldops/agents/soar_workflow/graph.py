"""SOAR Workflow Orchestrator Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SOARWorkflowState
from .nodes import (
    enrich_context,
    execute_containment,
    execute_eradication,
    intake_and_classify,
    recover_and_report,
)
from .tools import SOARWorkflowToolkit


def build_graph(toolkit: SOARWorkflowToolkit) -> StateGraph:
    """Build the SOAR Workflow Orchestrator agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _intake(state: Any) -> dict[str, Any]:
        return await intake_and_classify(_to_dict(state), toolkit)

    async def _enrich(state: Any) -> dict[str, Any]:
        return await enrich_context(_to_dict(state), toolkit)

    async def _contain(state: Any) -> dict[str, Any]:
        return await execute_containment(_to_dict(state), toolkit)

    async def _eradicate(state: Any) -> dict[str, Any]:
        return await execute_eradication(_to_dict(state), toolkit)

    async def _recover(state: Any) -> dict[str, Any]:
        return await recover_and_report(_to_dict(state), toolkit)

    graph = StateGraph(SOARWorkflowState)
    graph.add_node("intake_and_classify", _intake)
    graph.add_node("enrich_context", _enrich)
    graph.add_node("execute_containment", _contain)
    graph.add_node("execute_eradication", _eradicate)
    graph.add_node("recover_and_report", _recover)

    graph.set_entry_point("intake_and_classify")
    graph.add_edge("intake_and_classify", "enrich_context")
    graph.add_edge("enrich_context", "execute_containment")
    graph.add_edge("execute_containment", "execute_eradication")
    graph.add_edge("execute_eradication", "recover_and_report")
    graph.add_edge("recover_and_report", END)

    return graph


def create_soar_workflow_graph(
    siem_client: Any | None = None,
    edr_client: Any | None = None,
    firewall_client: Any | None = None,
    threat_intel_client: Any | None = None,
) -> StateGraph:
    """Create the SOAR Workflow Orchestrator agent graph with dependencies."""
    toolkit = SOARWorkflowToolkit(
        siem_client=siem_client,
        edr_client=edr_client,
        firewall_client=firewall_client,
        threat_intel_client=threat_intel_client,
    )
    return build_graph(toolkit)
