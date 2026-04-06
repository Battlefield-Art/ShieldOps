"""OTel Deployment Orchestrator Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import OTelDeployerState
from .nodes import (
    deploy_collectors,
    plan_deployments,
    validate_configs,
    verify_and_report,
)
from .tools import OTelDeployerToolkit


def build_graph(toolkit: OTelDeployerToolkit):  # type: ignore[no-untyped-def]
    """Build the otel_deployer agent graph (linear sequence)."""
    return build_linear_graph(
        OTelDeployerState,
        [
            ("plan", plan_deployments),
            ("validate", validate_configs),
            ("deploy", deploy_collectors),
            ("verify", verify_and_report),
        ],
        toolkit=toolkit,
    )


def create_otel_deployer_graph(
    k8s_client: Any | None = None,
    repository: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create and return the OTel Deployment Orchestrator graph.

    This is the main public entry point exported from __init__.py.
    """
    toolkit = OTelDeployerToolkit(
        k8s_client=k8s_client,
        repository=repository,
    )
    return build_graph(toolkit)
