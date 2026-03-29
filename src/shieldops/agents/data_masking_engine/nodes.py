"""Data Masking Engine Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.data_masking_engine.models import DataMaskingEngineState
from shieldops.agents.data_masking_engine.tools import DataMaskingEngineToolkit

logger = structlog.get_logger()

_toolkit: DataMaskingEngineToolkit | None = None


def set_toolkit(toolkit: DataMaskingEngineToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> DataMaskingEngineToolkit:
    if _toolkit is None:
        return DataMaskingEngineToolkit()
    return _toolkit


async def discover_data(
    state: DataMaskingEngineState,
) -> dict[str, Any]:
    """Execute discover_data."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_data",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_data done in {dur:.0f}ms",
        ],
    }


async def classify_sensitivity(
    state: DataMaskingEngineState,
) -> dict[str, Any]:
    """Execute classify_sensitivity."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "classify_sensitivity",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"classify_sensitivity done in {dur:.0f}ms",
        ],
    }


async def select_technique(
    state: DataMaskingEngineState,
) -> dict[str, Any]:
    """Execute select_technique."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "select_technique",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"select_technique done in {dur:.0f}ms",
        ],
    }


async def apply_masks(
    state: DataMaskingEngineState,
) -> dict[str, Any]:
    """Execute apply_masks."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "apply_masks",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"apply_masks done in {dur:.0f}ms",
        ],
    }


async def validate(
    state: DataMaskingEngineState,
) -> dict[str, Any]:
    """Execute validate."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "validate",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"validate done in {dur:.0f}ms",
        ],
    }


async def report(
    state: DataMaskingEngineState,
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
