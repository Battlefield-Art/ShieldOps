"""Key Lifecycle Manager Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.key_lifecycle_manager.models import KeyLifecycleManagerState
from shieldops.agents.key_lifecycle_manager.tools import KeyLifecycleManagerToolkit

logger = structlog.get_logger()

_toolkit: KeyLifecycleManagerToolkit | None = None


def _get_toolkit() -> KeyLifecycleManagerToolkit:
    if _toolkit is None:
        return KeyLifecycleManagerToolkit()
    return _toolkit


async def discover_keys(
    state: KeyLifecycleManagerState,
) -> dict[str, Any]:
    """Execute discover_keys."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_keys",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_keys done in {dur:.0f}ms",
        ],
    }


async def audit_ceremonies(
    state: KeyLifecycleManagerState,
) -> dict[str, Any]:
    """Execute audit_ceremonies."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "audit_ceremonies",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"audit_ceremonies done in {dur:.0f}ms",
        ],
    }


async def check_rotation(
    state: KeyLifecycleManagerState,
) -> dict[str, Any]:
    """Execute check_rotation."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "check_rotation",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_rotation done in {dur:.0f}ms",
        ],
    }


async def assess_compliance(
    state: KeyLifecycleManagerState,
) -> dict[str, Any]:
    """Execute assess_compliance."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_compliance",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_compliance done in {dur:.0f}ms",
        ],
    }


async def track_escrow(
    state: KeyLifecycleManagerState,
) -> dict[str, Any]:
    """Execute track_escrow."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "track_escrow",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"track_escrow done in {dur:.0f}ms",
        ],
    }


async def report(
    state: KeyLifecycleManagerState,
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
