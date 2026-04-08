"""Training Data Validator Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.training_data_validator.models import TrainingDataValidatorState
from shieldops.agents.training_data_validator.tools import TrainingDataValidatorToolkit

logger = structlog.get_logger()

_toolkit: TrainingDataValidatorToolkit | None = None


def _get_toolkit() -> TrainingDataValidatorToolkit:
    if _toolkit is None:
        return TrainingDataValidatorToolkit()
    return _toolkit


async def profile_data(
    state: TrainingDataValidatorState,
) -> dict[str, Any]:
    """Execute profile_data."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "profile_data",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"profile_data done in {duration:.0f}ms",
        ],
    }


async def check_labels(
    state: TrainingDataValidatorState,
) -> dict[str, Any]:
    """Execute check_labels."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "check_labels",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_labels done in {duration:.0f}ms",
        ],
    }


async def detect_poisoning(
    state: TrainingDataValidatorState,
) -> dict[str, Any]:
    """Execute detect_poisoning."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "detect_poisoning",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_poisoning done in {duration:.0f}ms",
        ],
    }


async def analyze_bias(
    state: TrainingDataValidatorState,
) -> dict[str, Any]:
    """Execute analyze_bias."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "analyze_bias",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_bias done in {duration:.0f}ms",
        ],
    }


async def validate_provenance(
    state: TrainingDataValidatorState,
) -> dict[str, Any]:
    """Execute validate_provenance."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "validate_provenance",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"validate_provenance done in {duration:.0f}ms",
        ],
    }


async def report(
    state: TrainingDataValidatorState,
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
