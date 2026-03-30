"""Cloud Cost Optimizer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import CloudCostOptimizerState
from .nodes import (
    analyze_spending,
    collect_billing,
    generate_report,
    identify_waste,
    implement_optimizations,
    recommend_savings,
)
from .tools import CloudCostOptimizerToolkit


def build_graph(
    toolkit: CloudCostOptimizerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Cost Optimizer graph.

    Flow:
        collect_billing -> analyze_spending
        -> identify_waste -> recommend_savings
        -> implement_optimizations -> report
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
        return await analyze_spending(
            _to_dict(state),
            toolkit,
        )

    async def _waste(
        state: Any,
    ) -> dict[str, Any]:
        return await identify_waste(
            _to_dict(state),
            toolkit,
        )

    async def _recommend(
        state: Any,
    ) -> dict[str, Any]:
        return await recommend_savings(
            _to_dict(state),
            toolkit,
        )

    async def _implement(
        state: Any,
    ) -> dict[str, Any]:
        return await implement_optimizations(
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

    graph = StateGraph(CloudCostOptimizerState)
    graph.add_node("collect_billing", _collect)
    graph.add_node("analyze_spending", _analyze)
    graph.add_node("identify_waste", _waste)
    graph.add_node("recommend_savings", _recommend)
    graph.add_node(
        "implement_optimizations",
        _implement,
    )
    graph.add_node("report", _report)

    graph.set_entry_point("collect_billing")
    graph.add_edge(
        "collect_billing",
        "analyze_spending",
    )
    graph.add_edge(
        "analyze_spending",
        "identify_waste",
    )
    graph.add_edge(
        "identify_waste",
        "recommend_savings",
    )
    graph.add_edge(
        "recommend_savings",
        "implement_optimizations",
    )
    graph.add_edge(
        "implement_optimizations",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_cloud_cost_optimizer_graph(
    billing_api: Any | None = None,
    cloud_provider: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Cost Optimizer graph."""
    toolkit = CloudCostOptimizerToolkit(
        billing_api=billing_api,
        cloud_provider=cloud_provider,
    )
    return build_graph(toolkit)
