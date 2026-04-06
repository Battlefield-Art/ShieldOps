"""Cloud Cost Optimizer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: CloudCostOptimizerToolkit):  # type: ignore[no-untyped-def]
    """Build the cloud_cost_optimizer agent graph (linear sequence)."""
    return build_linear_graph(
        CloudCostOptimizerState,
        [
            ("collect_billing", collect_billing),
            ("analyze_spending", analyze_spending),
            ("identify_waste", identify_waste),
            ("recommend_savings", recommend_savings),
            ("implement_optimizations", implement_optimizations),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


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
