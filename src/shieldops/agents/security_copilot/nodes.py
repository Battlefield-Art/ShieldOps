"""Security Copilot Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.security_copilot.models import SecurityCopilotState
from shieldops.agents.security_copilot.tools import SecurityCopilotToolkit

logger = structlog.get_logger()

_toolkit: SecurityCopilotToolkit | None = None


def set_toolkit(toolkit: SecurityCopilotToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityCopilotToolkit:
    if _toolkit is None:
        return SecurityCopilotToolkit()
    return _toolkit


async def parse_query(
    state: SecurityCopilotState,
) -> dict[str, Any]:
    """Execute parse_query."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "parse_query",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"parse_query done in {dur:.0f}ms",
        ],
    }


async def search_context(
    state: SecurityCopilotState,
) -> dict[str, Any]:
    """Execute search_context."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "search_context",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"search_context done in {dur:.0f}ms",
        ],
    }


async def analyze_data(
    state: SecurityCopilotState,
) -> dict[str, Any]:
    """Execute analyze_data."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_data",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_data done in {dur:.0f}ms",
        ],
    }


async def generate_response(
    state: SecurityCopilotState,
) -> dict[str, Any]:
    """Execute generate_response."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "generate_response",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"generate_response done in {dur:.0f}ms",
        ],
    }


async def validate_accuracy(
    state: SecurityCopilotState,
) -> dict[str, Any]:
    """Execute validate_accuracy."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "validate_accuracy",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"validate_accuracy done in {dur:.0f}ms",
        ],
    }


async def report(
    state: SecurityCopilotState,
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
