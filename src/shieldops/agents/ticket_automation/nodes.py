"""Ticket Automation Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.ticket_automation.models import TicketAutomationState
from shieldops.agents.ticket_automation.tools import TicketAutomationToolkit

logger = structlog.get_logger()

_toolkit: TicketAutomationToolkit | None = None


def _get_toolkit() -> TicketAutomationToolkit:
    if _toolkit is None:
        return TicketAutomationToolkit()
    return _toolkit


async def classify_event(
    state: TicketAutomationState,
) -> dict[str, Any]:
    """Execute classify_event."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "classify_event",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"classify_event done in {dur:.0f}ms",
        ],
    }


async def create_ticket(
    state: TicketAutomationState,
) -> dict[str, Any]:
    """Execute create_ticket."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "create_ticket",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"create_ticket done in {dur:.0f}ms",
        ],
    }


async def assign_owner(
    state: TicketAutomationState,
) -> dict[str, Any]:
    """Execute assign_owner."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assign_owner",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assign_owner done in {dur:.0f}ms",
        ],
    }


async def set_sla(
    state: TicketAutomationState,
) -> dict[str, Any]:
    """Execute set_sla."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "set_sla",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"set_sla done in {dur:.0f}ms",
        ],
    }


async def track(
    state: TicketAutomationState,
) -> dict[str, Any]:
    """Execute track."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "track",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"track done in {dur:.0f}ms",
        ],
    }


async def report(
    state: TicketAutomationState,
) -> dict[str, Any]:
    """Execute report."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "report",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"report done in {dur:.0f}ms",
        ],
    }
