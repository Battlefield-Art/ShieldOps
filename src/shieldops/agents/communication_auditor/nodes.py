"""Communication Auditor Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.communication_auditor.models import CommunicationAuditorState
from shieldops.agents.communication_auditor.tools import CommunicationAuditorToolkit

logger = structlog.get_logger()

_toolkit: CommunicationAuditorToolkit | None = None


def set_toolkit(toolkit: CommunicationAuditorToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> CommunicationAuditorToolkit:
    if _toolkit is None:
        return CommunicationAuditorToolkit()
    return _toolkit


async def collect_messages(
    state: CommunicationAuditorState,
) -> dict[str, Any]:
    """Execute collect_messages."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "collect_messages",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_messages done in {duration:.0f}ms",
        ],
    }


async def classify(
    state: CommunicationAuditorState,
) -> dict[str, Any]:
    """Execute classify."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "classify",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"classify done in {duration:.0f}ms",
        ],
    }


async def check_compliance(
    state: CommunicationAuditorState,
) -> dict[str, Any]:
    """Execute check_compliance."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "check_compliance",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_compliance done in {duration:.0f}ms",
        ],
    }


async def flag_violations(
    state: CommunicationAuditorState,
) -> dict[str, Any]:
    """Execute flag_violations."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "flag_violations",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"flag_violations done in {duration:.0f}ms",
        ],
    }


async def generate_report(
    state: CommunicationAuditorState,
) -> dict[str, Any]:
    """Execute generate_report."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "generate_report",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"generate_report done in {duration:.0f}ms",
        ],
    }


async def report(
    state: CommunicationAuditorState,
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
