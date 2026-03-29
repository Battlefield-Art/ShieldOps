"""Privileged Session Recorder Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.privileged_session_recorder.models import PrivilegedSessionRecorderState
from shieldops.agents.privileged_session_recorder.tools import PrivilegedSessionRecorderToolkit

logger = structlog.get_logger()

_toolkit: PrivilegedSessionRecorderToolkit | None = None


def set_toolkit(toolkit: PrivilegedSessionRecorderToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> PrivilegedSessionRecorderToolkit:
    if _toolkit is None:
        return PrivilegedSessionRecorderToolkit()
    return _toolkit


async def detect_session(
    state: PrivilegedSessionRecorderState,
) -> dict[str, Any]:
    """Execute detect_session."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "detect_session",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_session done in {dur:.0f}ms",
        ],
    }


async def start_recording(
    state: PrivilegedSessionRecorderState,
) -> dict[str, Any]:
    """Execute start_recording."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "start_recording",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"start_recording done in {dur:.0f}ms",
        ],
    }


async def monitor_commands(
    state: PrivilegedSessionRecorderState,
) -> dict[str, Any]:
    """Execute monitor_commands."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "monitor_commands",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"monitor_commands done in {dur:.0f}ms",
        ],
    }


async def detect_anomalies(
    state: PrivilegedSessionRecorderState,
) -> dict[str, Any]:
    """Execute detect_anomalies."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "detect_anomalies",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_anomalies done in {dur:.0f}ms",
        ],
    }


async def archive(
    state: PrivilegedSessionRecorderState,
) -> dict[str, Any]:
    """Execute archive."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "archive",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"archive done in {dur:.0f}ms",
        ],
    }


async def report(
    state: PrivilegedSessionRecorderState,
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
