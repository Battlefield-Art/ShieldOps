"""Just In Time Access Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.just_in_time_access.models import JustInTimeAccessState
from shieldops.agents.just_in_time_access.tools import JustInTimeAccessToolkit

logger = structlog.get_logger()

_toolkit: JustInTimeAccessToolkit | None = None


def _get_toolkit() -> JustInTimeAccessToolkit:
    if _toolkit is None:
        return JustInTimeAccessToolkit()
    return _toolkit


async def receive_request(
    state: JustInTimeAccessState,
) -> dict[str, Any]:
    """Execute receive_request."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "receive_request",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"receive_request done in {dur:.0f}ms",
        ],
    }


async def evaluate_policy(
    state: JustInTimeAccessState,
) -> dict[str, Any]:
    """Execute evaluate_policy."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "evaluate_policy",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"evaluate_policy done in {dur:.0f}ms",
        ],
    }


async def provision_access(
    state: JustInTimeAccessState,
) -> dict[str, Any]:
    """Execute provision_access."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "provision_access",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"provision_access done in {dur:.0f}ms",
        ],
    }


async def monitor_session(
    state: JustInTimeAccessState,
) -> dict[str, Any]:
    """Execute monitor_session."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "monitor_session",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"monitor_session done in {dur:.0f}ms",
        ],
    }


async def revoke_access(
    state: JustInTimeAccessState,
) -> dict[str, Any]:
    """Execute revoke_access."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "revoke_access",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"revoke_access done in {dur:.0f}ms",
        ],
    }


async def report(
    state: JustInTimeAccessState,
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
