"""Unified Cloud Security Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import UnifiedCloudSecurityState
from .nodes import (
    assess_posture,
    collect_cloud_state,
    detect_threats,
    orchestrate_response,
    prioritize_risks,
    report,
)
from .tools import UnifiedCloudSecurityToolkit


def build_graph(toolkit: UnifiedCloudSecurityToolkit):  # type: ignore[no-untyped-def]
    """Build the unified_cloud_security agent graph (linear sequence)."""
    return build_linear_graph(
        UnifiedCloudSecurityState,
        [
            ("collect_cloud_state", collect_cloud_state),
            ("assess_posture", assess_posture),
            ("detect_threats", detect_threats),
            ("prioritize_risks", prioritize_risks),
            ("orchestrate_response", orchestrate_response),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_unified_cloud_security_graph(
    aws_client: Any | None = None,
    gcp_client: Any | None = None,
    azure_client: Any | None = None,
    k8s_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Unified Cloud Security graph."""
    toolkit = UnifiedCloudSecurityToolkit(
        aws_client=aws_client,
        gcp_client=gcp_client,
        azure_client=azure_client,
        k8s_client=k8s_client,
    )
    return build_graph(toolkit)
