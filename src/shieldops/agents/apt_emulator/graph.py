"""LangGraph workflow for the APT Emulator Agent."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.apt_emulator.models import (
    APTEmulatorState,
)
from shieldops.agents.apt_emulator.nodes import (
    design_campaign,
    execute_recon,
    report,
    simulate_access,
    test_exfil,
    test_lateral,
    test_persistence,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def build_graph(
    toolkit: object | None = None,
) -> StateGraph:
    """Build the APT Emulator LangGraph workflow.

    Workflow::

        design_campaign -> execute_recon
            -> simulate_access -> test_persistence
            -> test_lateral -> test_exfil -> report
            -> END
    """
    _agent = "apt_emulator"
    graph = StateGraph(APTEmulatorState)

    graph.add_node(
        "design_campaign",
        traced_node("apt_emulator.design_campaign", _agent)(design_campaign),
    )
    graph.add_node(
        "execute_recon",
        traced_node("apt_emulator.execute_recon", _agent)(execute_recon),
    )
    graph.add_node(
        "simulate_access",
        traced_node("apt_emulator.simulate_access", _agent)(simulate_access),
    )
    graph.add_node(
        "test_persistence",
        traced_node("apt_emulator.test_persistence", _agent)(test_persistence),
    )
    graph.add_node(
        "test_lateral",
        traced_node("apt_emulator.test_lateral", _agent)(test_lateral),
    )
    graph.add_node(
        "test_exfil",
        traced_node("apt_emulator.test_exfil", _agent)(test_exfil),
    )
    graph.add_node(
        "report",
        traced_node("apt_emulator.report", _agent)(report),
    )

    graph.set_entry_point("design_campaign")
    graph.add_edge("design_campaign", "execute_recon")
    graph.add_edge("execute_recon", "simulate_access")
    graph.add_edge("simulate_access", "test_persistence")
    graph.add_edge("test_persistence", "test_lateral")
    graph.add_edge("test_lateral", "test_exfil")
    graph.add_edge("test_exfil", "report")
    graph.add_edge("report", END)

    return graph


def create_apt_emulator_graph() -> StateGraph:
    """Factory to create the APT Emulator graph."""
    return build_graph()
