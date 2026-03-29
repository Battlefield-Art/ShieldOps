"""Tokenization Manager Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.tokenization_manager.models import TokenizationManagerState
from shieldops.agents.tokenization_manager.tools import TokenizationManagerToolkit

logger = structlog.get_logger()

_toolkit: TokenizationManagerToolkit | None = None


def set_toolkit(toolkit: TokenizationManagerToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> TokenizationManagerToolkit:
    if _toolkit is None:
        return TokenizationManagerToolkit()
    return _toolkit


async def discover_fields(
    state: TokenizationManagerState,
) -> dict[str, Any]:
    """Execute discover_fields."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_fields",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_fields done in {dur:.0f}ms",
        ],
    }


async def generate_tokens(
    state: TokenizationManagerState,
) -> dict[str, Any]:
    """Execute generate_tokens."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "generate_tokens",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"generate_tokens done in {dur:.0f}ms",
        ],
    }


async def map_vault(
    state: TokenizationManagerState,
) -> dict[str, Any]:
    """Execute map_vault."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "map_vault",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"map_vault done in {dur:.0f}ms",
        ],
    }


async def validate_integrity(
    state: TokenizationManagerState,
) -> dict[str, Any]:
    """Execute validate_integrity."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "validate_integrity",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"validate_integrity done in {dur:.0f}ms",
        ],
    }


async def rotate(
    state: TokenizationManagerState,
) -> dict[str, Any]:
    """Execute rotate."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "rotate",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"rotate done in {dur:.0f}ms",
        ],
    }


async def report(
    state: TokenizationManagerState,
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
