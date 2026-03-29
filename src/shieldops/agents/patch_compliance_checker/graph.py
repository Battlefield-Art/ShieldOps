"""Patch Compliance Checker Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import PatchComplianceCheckerState
from .nodes import (
    assess_risk,
    check_sla,
    generate_report,
    inventory_systems,
    scan_patches,
    schedule_rollout,
)
from .tools import PatchComplianceCheckerToolkit


def _traced_node(
    func,  # noqa: ANN001
    toolkit: PatchComplianceCheckerToolkit,
) -> Any:
    async def _wrapper(state: Any) -> dict[str, Any]:
        d = state.model_dump() if hasattr(state, "model_dump") else dict(state)
        try:
            return await func(d, toolkit)
        except Exception as exc:
            return {"error": str(exc)}

    return _wrapper


def _check_error(state: Any) -> str:
    err = state.error if hasattr(state, "error") else state.get("error", "")
    return "error_end" if err else "continue"


def build_graph(
    toolkit: PatchComplianceCheckerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Patch Compliance Checker agent graph."""

    graph = StateGraph(PatchComplianceCheckerState)

    graph.add_node("inventory_systems", _traced_node(inventory_systems, toolkit))
    graph.add_node("scan_patches", _traced_node(scan_patches, toolkit))
    graph.add_node("assess_risk", _traced_node(assess_risk, toolkit))
    graph.add_node("check_sla", _traced_node(check_sla, toolkit))
    graph.add_node("schedule_rollout", _traced_node(schedule_rollout, toolkit))
    graph.add_node("report", _traced_node(generate_report, toolkit))
    graph.add_node("error_end", lambda s: {"error": s.get("error", "")})

    graph.set_entry_point("inventory_systems")
    graph.add_conditional_edges(
        "inventory_systems",
        _check_error,
        {"continue": "scan_patches", "error_end": "error_end"},
    )
    graph.add_edge("scan_patches", "assess_risk")
    graph.add_edge("assess_risk", "check_sla")
    graph.add_edge("check_sla", "schedule_rollout")
    graph.add_edge("schedule_rollout", "report")
    graph.add_edge("report", END)
    graph.add_edge("error_end", END)

    return graph


def create_patch_compliance_checker_graph(
    wsus_client: Any | None = None,
    vuln_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Patch Compliance Checker graph with deps."""
    toolkit = PatchComplianceCheckerToolkit(
        wsus_client=wsus_client,
        vuln_client=vuln_client,
    )
    return build_graph(toolkit)
