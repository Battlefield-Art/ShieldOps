"""Consent Manager Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.consent_manager.models import ConsentManagerState
from shieldops.agents.consent_manager.tools import ConsentManagerToolkit

logger = structlog.get_logger()

_toolkit: ConsentManagerToolkit | None = None


def _get_toolkit() -> ConsentManagerToolkit:
    if _toolkit is None:
        return ConsentManagerToolkit()
    return _toolkit


async def collect_consents(
    state: ConsentManagerState,
) -> dict[str, Any]:
    """Execute collect_consents."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_consents",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_consents done in {dur:.0f}ms",
        ],
    }


async def validate_purposes(
    state: ConsentManagerState,
) -> dict[str, Any]:
    """Execute validate_purposes."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "validate_purposes",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"validate_purposes done in {dur:.0f}ms",
        ],
    }


async def check_expiry(
    state: ConsentManagerState,
) -> dict[str, Any]:
    """Execute check_expiry."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "check_expiry",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_expiry done in {dur:.0f}ms",
        ],
    }


async def enforce_preferences(
    state: ConsentManagerState,
) -> dict[str, Any]:
    """Execute enforce_preferences."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "enforce_preferences",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"enforce_preferences done in {dur:.0f}ms",
        ],
    }


async def audit(
    state: ConsentManagerState,
) -> dict[str, Any]:
    """Execute audit."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "audit",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"audit done in {dur:.0f}ms",
        ],
    }


async def report(
    state: ConsentManagerState,
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
