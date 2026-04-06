"""LangGraph workflow definition for the Digital Twin Security Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import DigitalTwinSecurityState
from .nodes import (
    analyze_results,
    configure_environment,
    create_twin,
    execute_simulations,
    generate_report,
    validate_posture,
)
from .tools import DigitalTwinSecurityToolkit


def build_graph(toolkit: DigitalTwinSecurityToolkit):  # type: ignore[no-untyped-def]
    """Build the digital_twin_security agent graph (linear sequence)."""
    return build_linear_graph(
        DigitalTwinSecurityState,
        [
            ("create_twin", create_twin),
            ("configure_environment", configure_environment),
            ("execute_simulations", execute_simulations),
            ("analyze_results", analyze_results),
            ("validate_posture", validate_posture),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_digital_twin_security_graph(
    **clients: Any,
) -> StateGraph:
    """Factory function to create a Digital Twin Security graph with injected clients."""
    toolkit = DigitalTwinSecurityToolkit(
        cloud_connector=clients.get("cloud_connector"),
        network_scanner=clients.get("network_scanner"),
        identity_provider=clients.get("identity_provider"),
        policy_engine=clients.get("policy_engine"),
        repository=clients.get("repository"),
    )
    from shieldops.agents.digital_twin_security.nodes import set_toolkit

    set_toolkit(toolkit)
    return build_graph(toolkit)
