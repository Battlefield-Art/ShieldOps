"""LangGraph workflow for the APT Emulator Agent."""

from __future__ import annotations

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import APTEmulatorState
from .nodes import (
    design_campaign,
    execute_recon,
    report,
    simulate_access,
    test_exfil,
    test_lateral,
    test_persistence,
)


def build_graph(toolkit: object = None):  # type: ignore[no-untyped-def]
    """Build the apt_emulator agent graph (linear sequence)."""
    return build_linear_graph(
        APTEmulatorState,
        [
            ("design_campaign", design_campaign),
            ("execute_recon", execute_recon),
            ("simulate_access", simulate_access),
            ("test_persistence", test_persistence),
            ("test_lateral", test_lateral),
            ("test_exfil", test_exfil),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_apt_emulator_graph() -> StateGraph:
    """Factory to create the APT Emulator graph."""
    return build_graph()
