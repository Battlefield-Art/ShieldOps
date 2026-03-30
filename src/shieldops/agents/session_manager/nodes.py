"""Session Manager Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.session_manager.models import (
    SessionManagerState,
)
from shieldops.agents.session_manager.tools import (
    SessionManagerToolkit,
)

logger = structlog.get_logger()

_toolkit: SessionManagerToolkit | None = None


def set_toolkit(
    toolkit: SessionManagerToolkit,
) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SessionManagerToolkit:
    if _toolkit is None:
        return SessionManagerToolkit()
    return _toolkit


async def discover_sessions(
    state: SessionManagerState,
) -> dict[str, Any]:
    """Execute discover_sessions."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.discover_sessions()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_sessions",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_sessions done in {dur:.0f}ms",
        ],
    }


async def analyze_patterns(
    state: SessionManagerState,
) -> dict[str, Any]:
    """Execute analyze_patterns."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.analyze_patterns()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_patterns",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_patterns done in {dur:.0f}ms",
        ],
    }


async def detect_hijacking(
    state: SessionManagerState,
) -> dict[str, Any]:
    """Execute detect_hijacking."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.detect_hijacking()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "detect_hijacking",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_hijacking done in {dur:.0f}ms",
        ],
    }


async def enforce_timeouts(
    state: SessionManagerState,
) -> dict[str, Any]:
    """Execute enforce_timeouts."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.enforce_timeouts()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "enforce_timeouts",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"enforce_timeouts done in {dur:.0f}ms",
        ],
    }


async def revoke_suspicious(
    state: SessionManagerState,
) -> dict[str, Any]:
    """Execute revoke_suspicious."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.revoke_suspicious()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "revoke_suspicious",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"revoke_suspicious done in {dur:.0f}ms",
        ],
    }


async def report(
    state: SessionManagerState,
) -> dict[str, Any]:
    """Generate final report."""
    return {
        "current_step": "report",
        "stats": {
            "total_findings": len(state.findings),
            "steps": len(state.reasoning_chain),
        },
        "reasoning_chain": [
            *state.reasoning_chain,
            "report generated",
        ],
    }
