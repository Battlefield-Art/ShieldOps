"""Cloud Billing Protector Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: CloudBillingProtectorToolkit):  # type: ignore[no-untyped-def]
    """Build the cloud_billing_protector agent graph (linear sequence)."""
    return build_linear_graph(
        CloudBillingProtectorState,
        [
            ("collect_billing", collect_billing),
            ("analyze_patterns", analyze_patterns),
            ("detect_anomalies", detect_anomalies),
            ("classify_fraud", classify_fraud),
            ("enforce_limits", enforce_limits),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


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
