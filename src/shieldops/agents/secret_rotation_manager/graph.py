"""Secret Rotation Manager Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SecretRotationManagerState
from .nodes import (
    assess_rotation,
    execute_rotation,
    generate_report,
    inventory_secrets,
    plan_rotation,
    verify_health,
)
from .tools import SecretRotationManagerToolkit


def build_graph(toolkit: SecretRotationManagerToolkit):  # type: ignore[no-untyped-def]
    """Build the secret_rotation_manager agent graph (linear sequence)."""
    return build_linear_graph(
        SecretRotationManagerState,
        [
            ("inventory_secrets", inventory_secrets),
            ("assess_rotation", assess_rotation),
            ("plan_rotation", plan_rotation),
            ("execute_rotation", execute_rotation),
            ("verify_health", verify_health),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_secret_rotation_manager_graph(
    vault_client: Any | None = None,
    cloud_provider: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Secret Rotation Manager graph."""
    toolkit = SecretRotationManagerToolkit(
        vault_client=vault_client,
        cloud_provider=cloud_provider,
    )
    return build_graph(toolkit)
