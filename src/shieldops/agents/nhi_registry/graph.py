"""NHI Registry Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import NHIRegistryState
from .nodes import (
    assess_risk,
    classify_identities,
    detect_shadow_ai,
    generate_recommendations,
    report,
    scan_cicd,
    scan_cloud_iam,
    scan_kubernetes,
)
from .tools import NHIRegistryToolkit


def build_graph(toolkit: NHIRegistryToolkit):  # type: ignore[no-untyped-def]
    """Build the nhi_registry agent graph (linear sequence)."""
    return build_linear_graph(
        NHIRegistryState,
        [
            ("scan_cloud_iam", scan_cloud_iam),
            ("scan_kubernetes", scan_kubernetes),
            ("scan_cicd", scan_cicd),
            ("detect_shadow_ai", detect_shadow_ai),
            ("classify_identities", classify_identities),
            ("assess_risk", assess_risk),
            ("generate_recommendations", generate_recommendations),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_nhi_registry_graph(
    aws_client: Any | None = None,
    gcp_client: Any | None = None,
    azure_client: Any | None = None,
    k8s_client: Any | None = None,
    github_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the NHI Registry agent graph with dependencies."""
    toolkit = NHIRegistryToolkit(
        aws_client=aws_client,
        gcp_client=gcp_client,
        azure_client=azure_client,
        k8s_client=k8s_client,
        github_client=github_client,
    )
    return build_graph(toolkit)
