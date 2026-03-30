"""Vendor Compliance Assessor Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

from .models import VendorComplianceAssessorState
from .nodes import (
    assess_risk,
    collect_questionnaires,
    generate_report,
    inventory_vendors,
    report,
    score_compliance,
)
from .tools import VendorComplianceAssessorToolkit

_AGENT = "vendor_compliance_assessor"


def _check_error(
    state: VendorComplianceAssessorState,
) -> str:
    if state.error:
        return "report"
    return "continue"


def build_graph(
    toolkit: VendorComplianceAssessorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Vendor Compliance Assessor graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _inventory(
        state: Any,
    ) -> dict[str, Any]:
        return await inventory_vendors(
            _to_dict(state),
            toolkit,
        )

    async def _questionnaires(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_questionnaires(
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

    async def _score(
        state: Any,
    ) -> dict[str, Any]:
        return await score_compliance(
            _to_dict(state),
            toolkit,
        )

    async def _gen_report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(VendorComplianceAssessorState)
    graph.add_node(
        "inventory_vendors",
        traced_node("vca.inventory", _AGENT)(_inventory),
    )
    graph.add_node(
        "collect_questionnaires",
        traced_node("vca.questionnaires", _AGENT)(_questionnaires),
    )
    graph.add_node(
        "assess_risk",
        traced_node("vca.risk", _AGENT)(_risk),
    )
    graph.add_node(
        "score_compliance",
        traced_node("vca.score", _AGENT)(_score),
    )
    graph.add_node(
        "generate_report",
        traced_node("vca.gen_report", _AGENT)(_gen_report),
    )
    graph.add_node(
        "report",
        traced_node("vca.report", _AGENT)(_report),
    )

    graph.set_entry_point("inventory_vendors")
    graph.add_edge(
        "inventory_vendors",
        "collect_questionnaires",
    )
    graph.add_edge(
        "collect_questionnaires",
        "assess_risk",
    )
    graph.add_edge("assess_risk", "score_compliance")
    graph.add_edge(
        "score_compliance",
        "generate_report",
    )
    graph.add_edge("generate_report", "report")
    graph.add_edge("report", END)

    return graph


def create_vendor_compliance_assessor_graph(
    vendor_db: Any | None = None,
    questionnaire_api: Any | None = None,
    risk_engine: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Vendor Compliance Assessor graph."""
    toolkit = VendorComplianceAssessorToolkit(
        vendor_db=vendor_db,
        questionnaire_api=questionnaire_api,
        risk_engine=risk_engine,
    )
    return build_graph(toolkit)
