"""SOX Auditor Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.sox_auditor.models import SOXAuditorState
from shieldops.agents.sox_auditor.tools import SOXAuditorToolkit

logger = structlog.get_logger()

_toolkit: SOXAuditorToolkit | None = None


def set_toolkit(toolkit: SOXAuditorToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SOXAuditorToolkit:
    if _toolkit is None:
        return SOXAuditorToolkit()
    return _toolkit


async def identify_controls(
    state: SOXAuditorState,
) -> dict[str, Any]:
    """Execute identify_controls."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "identify_controls",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_controls done in {duration:.0f}ms",
        ],
    }


async def test_controls(
    state: SOXAuditorState,
) -> dict[str, Any]:
    """Execute test_controls."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "test_controls",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"test_controls done in {duration:.0f}ms",
        ],
    }


async def evaluate_deficiencies(
    state: SOXAuditorState,
) -> dict[str, Any]:
    """Execute evaluate_deficiencies."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "evaluate_deficiencies",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"evaluate_deficiencies done in {duration:.0f}ms",
        ],
    }


async def remediate(
    state: SOXAuditorState,
) -> dict[str, Any]:
    """Execute remediate."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "remediate",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"remediate done in {duration:.0f}ms",
        ],
    }


async def document(
    state: SOXAuditorState,
) -> dict[str, Any]:
    """Execute document."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "document",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"document done in {duration:.0f}ms",
        ],
    }


async def report(
    state: SOXAuditorState,
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
