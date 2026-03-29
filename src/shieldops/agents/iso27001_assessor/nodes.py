"""ISO 27001 Assessor Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.iso27001_assessor.models import ISO27001AssessorState
from shieldops.agents.iso27001_assessor.tools import ISO27001AssessorToolkit

logger = structlog.get_logger()

_toolkit: ISO27001AssessorToolkit | None = None


def set_toolkit(toolkit: ISO27001AssessorToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ISO27001AssessorToolkit:
    if _toolkit is None:
        return ISO27001AssessorToolkit()
    return _toolkit


async def scope_isms(
    state: ISO27001AssessorState,
) -> dict[str, Any]:
    """Execute scope_isms."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "scope_isms",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"scope_isms done in {duration:.0f}ms",
        ],
    }


async def assess_controls(
    state: ISO27001AssessorState,
) -> dict[str, Any]:
    """Execute assess_controls."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "assess_controls",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_controls done in {duration:.0f}ms",
        ],
    }


async def identify_gaps(
    state: ISO27001AssessorState,
) -> dict[str, Any]:
    """Execute identify_gaps."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "identify_gaps",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_gaps done in {duration:.0f}ms",
        ],
    }


async def risk_treatment(
    state: ISO27001AssessorState,
) -> dict[str, Any]:
    """Execute risk_treatment."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "risk_treatment",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"risk_treatment done in {duration:.0f}ms",
        ],
    }


async def soa(
    state: ISO27001AssessorState,
) -> dict[str, Any]:
    """Execute soa."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "soa",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"soa done in {duration:.0f}ms",
        ],
    }


async def report(
    state: ISO27001AssessorState,
) -> dict[str, Any]:
    """Execute report."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "report",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"report done in {duration:.0f}ms",
        ],
    }
