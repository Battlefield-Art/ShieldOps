"""LangGraph workflow definition for the Digital Twin Security Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.digital_twin_security.models import DigitalTwinSecurityState
from shieldops.agents.digital_twin_security.nodes import (
    analyze_results,
    configure_environment,
    create_twin,
    execute_simulations,
    generate_report,
    validate_posture,
)
from shieldops.agents.digital_twin_security.tools import DigitalTwinSecurityToolkit
from shieldops.agents.tracing import traced_node


def build_graph(toolkit: DigitalTwinSecurityToolkit) -> StateGraph:
    """Build the Digital Twin Security Agent LangGraph workflow.

    Workflow:
        create_twin -> configure_environment -> execute_simulations
            -> analyze_results -> validate_posture -> generate_report -> END
    """
    graph = StateGraph(DigitalTwinSecurityState)

    _agent = "digital_twin_security"
    graph.add_node(
        "create_twin",
        traced_node("digital_twin_security.create_twin", _agent)(create_twin),
    )
    graph.add_node(
        "configure_environment",
        traced_node("digital_twin_security.configure_environment", _agent)(configure_environment),
    )
    graph.add_node(
        "execute_simulations",
        traced_node("digital_twin_security.execute_simulations", _agent)(execute_simulations),
    )
    graph.add_node(
        "analyze_results",
        traced_node("digital_twin_security.analyze_results", _agent)(analyze_results),
    )
    graph.add_node(
        "validate_posture",
        traced_node("digital_twin_security.validate_posture", _agent)(validate_posture),
    )
    graph.add_node(
        "generate_report",
        traced_node("digital_twin_security.generate_report", _agent)(generate_report),
    )

    # Define edges
    graph.set_entry_point("create_twin")
    graph.add_edge("create_twin", "configure_environment")
    graph.add_edge("configure_environment", "execute_simulations")
    graph.add_edge("execute_simulations", "analyze_results")
    graph.add_edge("analyze_results", "validate_posture")
    graph.add_edge("validate_posture", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


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
