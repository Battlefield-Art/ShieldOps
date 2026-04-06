"""Security Signal Correlator Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SecuritySignalCorrelatorState
from .nodes import (
    collect_signals,
    correlate,
    generate_incidents,
    generate_report,
    normalize,
    score_confidence,
)
from .tools import SecuritySignalCorrelatorToolkit


def build_graph(toolkit: SecuritySignalCorrelatorToolkit):  # type: ignore[no-untyped-def]
    """Build the security_signal_correlator agent graph (linear sequence)."""
    return build_linear_graph(
        SecuritySignalCorrelatorState,
        [
            ("collect_signals", collect_signals),
            ("normalize", normalize),
            ("correlate", correlate),
            ("score_confidence", score_confidence),
            ("generate_incidents", generate_incidents),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_security_signal_correlator_graph(
    signal_sources: Any | None = None,
    threat_intel: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security Signal Correlator graph."""
    toolkit = SecuritySignalCorrelatorToolkit(
        signal_sources=signal_sources,
        threat_intel=threat_intel,
    )
    return build_graph(toolkit)
