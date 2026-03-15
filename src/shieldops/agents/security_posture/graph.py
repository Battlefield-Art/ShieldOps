"""Security Posture Manager Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecurityPostureState
from .nodes import (
    assess_domains,
    generate_report,
    identify_gaps,
    prioritize_remediation,
)
from .tools import SecurityPostureToolkit


def build_graph(toolkit: SecurityPostureToolkit) -> StateGraph:
    """Build the Security Posture Manager agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_domains(_to_dict(state), toolkit)

    async def _identify_gaps(state: Any) -> dict[str, Any]:
        return await identify_gaps(_to_dict(state), toolkit)

    async def _prioritize(state: Any) -> dict[str, Any]:
        return await prioritize_remediation(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(SecurityPostureState)
    graph.add_node("assess_domains", _assess)
    graph.add_node("identify_gaps", _identify_gaps)
    graph.add_node("prioritize_remediation", _prioritize)
    graph.add_node("generate_report", _report)

    graph.set_entry_point("assess_domains")
    graph.add_edge("assess_domains", "identify_gaps")
    graph.add_edge("identify_gaps", "prioritize_remediation")
    graph.add_edge("prioritize_remediation", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_posture_graph(
    rba_client: Any | None = None,
    compliance_store: Any | None = None,
    vuln_scanner: Any | None = None,
    threat_intel: Any | None = None,
) -> StateGraph:
    """Create the Security Posture Manager agent graph with dependencies."""
    toolkit = SecurityPostureToolkit(
        rba_client=rba_client,
        compliance_store=compliance_store,
        vuln_scanner=vuln_scanner,
        threat_intel=threat_intel,
    )
    return build_graph(toolkit)
