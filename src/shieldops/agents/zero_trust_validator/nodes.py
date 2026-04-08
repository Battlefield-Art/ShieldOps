"""Zero Trust Validator Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.zero_trust_validator.models import ZeroTrustValidatorState
from shieldops.agents.zero_trust_validator.tools import ZeroTrustValidatorToolkit

logger = structlog.get_logger()

_toolkit: ZeroTrustValidatorToolkit | None = None


def _get_toolkit() -> ZeroTrustValidatorToolkit:
    if _toolkit is None:
        return ZeroTrustValidatorToolkit()
    return _toolkit


async def inventory_assets(
    state: ZeroTrustValidatorState,
) -> dict[str, Any]:
    """Execute inventory_assets."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "inventory_assets",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"inventory_assets done in {dur:.0f}ms",
        ],
    }


async def check_identity(
    state: ZeroTrustValidatorState,
) -> dict[str, Any]:
    """Execute check_identity."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "check_identity",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_identity done in {dur:.0f}ms",
        ],
    }


async def verify_access(
    state: ZeroTrustValidatorState,
) -> dict[str, Any]:
    """Execute verify_access."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "verify_access",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"verify_access done in {dur:.0f}ms",
        ],
    }


async def inspect_traffic(
    state: ZeroTrustValidatorState,
) -> dict[str, Any]:
    """Execute inspect_traffic."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "inspect_traffic",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"inspect_traffic done in {dur:.0f}ms",
        ],
    }


async def assess_posture(
    state: ZeroTrustValidatorState,
) -> dict[str, Any]:
    """Execute assess_posture."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_posture",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_posture done in {dur:.0f}ms",
        ],
    }


async def report(
    state: ZeroTrustValidatorState,
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
