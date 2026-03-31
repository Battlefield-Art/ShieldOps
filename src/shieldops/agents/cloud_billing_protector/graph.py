"""Cloud Billing Protector Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CloudBillingProtectorState
from .nodes import (
    analyze_patterns,
    classify_fraud,
    collect_billing,
    detect_anomalies,
    enforce_limits,
    generate_report,
)
from .tools import CloudBillingProtectorToolkit


def build_graph(
    toolkit: CloudBillingProtectorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Billing Protector graph.

    Flow:
        collect_billing -> analyze_patterns -> detect_anomalies
        -> classify_fraud -> enforce_limits -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_billing(
            _to_dict(state),
            toolkit,
        )

    async def _analyze(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_patterns(
            _to_dict(state),
            toolkit,
        )

    async def _detect(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_anomalies(
            _to_dict(state),
            toolkit,
        )

    async def _classify(
        state: Any,
    ) -> dict[str, Any]:
        return await classify_fraud(
            _to_dict(state),
            toolkit,
        )

    async def _enforce(
        state: Any,
    ) -> dict[str, Any]:
        return await enforce_limits(
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

    graph = StateGraph(CloudBillingProtectorState)
    graph.add_node("collect_billing", _collect)
    graph.add_node("analyze_patterns", _analyze)
    graph.add_node("detect_anomalies", _detect)
    graph.add_node("classify_fraud", _classify)
    graph.add_node("enforce_limits", _enforce)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_billing")
    graph.add_edge(
        "collect_billing",
        "analyze_patterns",
    )
    graph.add_edge(
        "analyze_patterns",
        "detect_anomalies",
    )
    graph.add_edge(
        "detect_anomalies",
        "classify_fraud",
    )
    graph.add_edge(
        "classify_fraud",
        "enforce_limits",
    )
    graph.add_edge(
        "enforce_limits",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_cloud_billing_protector_graph(
    billing_api: Any | None = None,
    budget_service: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Billing Protector graph."""
    toolkit = CloudBillingProtectorToolkit(
        billing_api=billing_api,
        budget_service=budget_service,
    )
    return build_graph(toolkit)
