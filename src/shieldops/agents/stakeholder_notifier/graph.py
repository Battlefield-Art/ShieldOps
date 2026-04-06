"""Stakeholder Notifier — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import StakeholderNotifierState
from .nodes import (
    assess_impact,
    compose_message,
    deliver_notification,
    identify_stakeholders,
    report,
    select_channels,
)
from .tools import StakeholderNotifierToolkit


def build_graph(toolkit: StakeholderNotifierToolkit):  # type: ignore[no-untyped-def]
    """Build the stakeholder_notifier agent graph (linear sequence)."""
    return build_linear_graph(
        StakeholderNotifierState,
        [
            ("identify_stakeholders", identify_stakeholders),
            ("assess_impact", assess_impact),
            ("compose_message", compose_message),
            ("select_channels", select_channels),
            ("deliver_notification", deliver_notification),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_stakeholder_notifier_graph(
    notification_service: Any | None = None,
    contact_directory: Any | None = None,
) -> StateGraph:
    """Factory to create the stakeholder notifier graph."""
    toolkit = StakeholderNotifierToolkit(
        notification_service=notification_service,
        contact_directory=contact_directory,
    )
    return build_graph(toolkit)
