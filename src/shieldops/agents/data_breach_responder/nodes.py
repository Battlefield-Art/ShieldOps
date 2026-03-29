"""Data Breach Responder Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.data_breach_responder.models import DataBreachResponderState
from shieldops.agents.data_breach_responder.tools import DataBreachResponderToolkit

logger = structlog.get_logger()

_toolkit: DataBreachResponderToolkit | None = None


def set_toolkit(toolkit: DataBreachResponderToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> DataBreachResponderToolkit:
    if _toolkit is None:
        return DataBreachResponderToolkit()
    return _toolkit


async def detect_breach(
    state: DataBreachResponderState,
) -> dict[str, Any]:
    """Execute detect_breach."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "detect_breach",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_breach done in {dur:.0f}ms",
        ],
    }


async def assess_scope(
    state: DataBreachResponderState,
) -> dict[str, Any]:
    """Execute assess_scope."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_scope",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_scope done in {dur:.0f}ms",
        ],
    }


async def contain(
    state: DataBreachResponderState,
) -> dict[str, Any]:
    """Execute contain."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "contain",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"contain done in {dur:.0f}ms",
        ],
    }


async def notify_authorities(
    state: DataBreachResponderState,
) -> dict[str, Any]:
    """Execute notify_authorities."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "notify_authorities",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"notify_authorities done in {dur:.0f}ms",
        ],
    }


async def notify_subjects(
    state: DataBreachResponderState,
) -> dict[str, Any]:
    """Execute notify_subjects."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "notify_subjects",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"notify_subjects done in {dur:.0f}ms",
        ],
    }


async def report(
    state: DataBreachResponderState,
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
