"""Stakeholder Notifier — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node

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

_AGENT = "stakeholder_notifier"


def _check_error(
    state: StakeholderNotifierState,
) -> str:
    if state.error:
        return "report"
    return "continue"


def build_graph(
    toolkit: StakeholderNotifierToolkit,
) -> StateGraph:
    """Build the Stakeholder Notifier graph."""

    def _d(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return dict(state) if not isinstance(state, dict) else state

    async def _identify(s: Any) -> dict[str, Any]:
        return await identify_stakeholders(_d(s))

    async def _impact(s: Any) -> dict[str, Any]:
        return await assess_impact(_d(s))

    async def _compose(s: Any) -> dict[str, Any]:
        return await compose_message(_d(s))

    async def _channels(s: Any) -> dict[str, Any]:
        return await select_channels(_d(s))

    async def _deliver(s: Any) -> dict[str, Any]:
        return await deliver_notification(_d(s))

    async def _report(s: Any) -> dict[str, Any]:
        return await report(_d(s))

    g = StateGraph(StakeholderNotifierState)
    g.add_node(
        "identify_stakeholders",
        traced_node("sn.identify", _AGENT)(_identify),
    )
    g.add_node(
        "assess_impact",
        traced_node("sn.impact", _AGENT)(_impact),
    )
    g.add_node(
        "compose_message",
        traced_node("sn.compose", _AGENT)(_compose),
    )
    g.add_node(
        "select_channels",
        traced_node("sn.channels", _AGENT)(_channels),
    )
    g.add_node(
        "deliver_notification",
        traced_node("sn.deliver", _AGENT)(_deliver),
    )
    g.add_node(
        "report",
        traced_node("sn.report", _AGENT)(_report),
    )

    g.set_entry_point("identify_stakeholders")
    g.add_edge(
        "identify_stakeholders",
        "assess_impact",
    )
    g.add_edge("assess_impact", "compose_message")
    g.add_edge("compose_message", "select_channels")
    g.add_edge(
        "select_channels",
        "deliver_notification",
    )
    g.add_edge("deliver_notification", "report")
    g.add_edge("report", END)

    return g


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
