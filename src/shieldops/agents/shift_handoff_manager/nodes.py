"""Shift Handoff Manager Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.shift_handoff_manager.models import ShiftHandoffManagerState
from shieldops.agents.shift_handoff_manager.tools import ShiftHandoffManagerToolkit

logger = structlog.get_logger()

_toolkit: ShiftHandoffManagerToolkit | None = None


def _get_toolkit() -> ShiftHandoffManagerToolkit:
    if _toolkit is None:
        return ShiftHandoffManagerToolkit()
    return _toolkit


async def collect_state(
    state: ShiftHandoffManagerState,
) -> dict[str, Any]:
    """Execute collect_state."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_state",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_state done in {dur:.0f}ms",
        ],
    }


async def summarize_incidents(
    state: ShiftHandoffManagerState,
) -> dict[str, Any]:
    """Execute summarize_incidents."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "summarize_incidents",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"summarize_incidents done in {dur:.0f}ms",
        ],
    }


async def document_actions(
    state: ShiftHandoffManagerState,
) -> dict[str, Any]:
    """Execute document_actions."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "document_actions",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"document_actions done in {dur:.0f}ms",
        ],
    }


async def brief_incoming(
    state: ShiftHandoffManagerState,
) -> dict[str, Any]:
    """Execute brief_incoming."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "brief_incoming",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"brief_incoming done in {dur:.0f}ms",
        ],
    }


async def transfer(
    state: ShiftHandoffManagerState,
) -> dict[str, Any]:
    """Execute transfer."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "transfer",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"transfer done in {dur:.0f}ms",
        ],
    }


async def report(
    state: ShiftHandoffManagerState,
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
