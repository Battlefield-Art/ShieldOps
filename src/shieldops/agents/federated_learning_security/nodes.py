"""Federated Learning Security Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.federated_learning_security.models import FederatedLearningSecurityState
from shieldops.agents.federated_learning_security.tools import FederatedLearningSecurityToolkit

logger = structlog.get_logger()

_toolkit: FederatedLearningSecurityToolkit | None = None


def _get_toolkit() -> FederatedLearningSecurityToolkit:
    if _toolkit is None:
        return FederatedLearningSecurityToolkit()
    return _toolkit


async def inspect_gradients(
    state: FederatedLearningSecurityState,
) -> dict[str, Any]:
    """Execute inspect_gradients."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "inspect_gradients",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"inspect_gradients done in {duration:.0f}ms",
        ],
    }


async def detect_poisoning(
    state: FederatedLearningSecurityState,
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


async def score_participants(
    state: FederatedLearningSecurityState,
) -> dict[str, Any]:
    """Execute score_participants."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "score_participants",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"score_participants done in {duration:.0f}ms",
        ],
    }


async def verify_aggregation(
    state: FederatedLearningSecurityState,
) -> dict[str, Any]:
    """Execute verify_aggregation."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "verify_aggregation",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"verify_aggregation done in {duration:.0f}ms",
        ],
    }


async def assess_risk(
    state: FederatedLearningSecurityState,
) -> dict[str, Any]:
    """Execute assess_risk."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "assess_risk",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_risk done in {duration:.0f}ms",
        ],
    }


async def report(
    state: FederatedLearningSecurityState,
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
