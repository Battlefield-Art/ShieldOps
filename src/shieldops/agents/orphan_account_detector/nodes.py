"""Orphan Account Detector Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.orphan_account_detector.models import OrphanAccountDetectorState
from shieldops.agents.orphan_account_detector.tools import OrphanAccountDetectorToolkit

logger = structlog.get_logger()

_toolkit: OrphanAccountDetectorToolkit | None = None


def _get_toolkit() -> OrphanAccountDetectorToolkit:
    if _toolkit is None:
        return OrphanAccountDetectorToolkit()
    return _toolkit


async def scan_accounts(
    state: OrphanAccountDetectorState,
) -> dict[str, Any]:
    """Execute scan_accounts."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "scan_accounts",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"scan_accounts done in {dur:.0f}ms",
        ],
    }


async def cross_reference_hr(
    state: OrphanAccountDetectorState,
) -> dict[str, Any]:
    """Execute cross_reference_hr."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "cross_reference_hr",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"cross_reference_hr done in {dur:.0f}ms",
        ],
    }


async def identify_orphans(
    state: OrphanAccountDetectorState,
) -> dict[str, Any]:
    """Execute identify_orphans."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "identify_orphans",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_orphans done in {dur:.0f}ms",
        ],
    }


async def classify_risk(
    state: OrphanAccountDetectorState,
) -> dict[str, Any]:
    """Execute classify_risk."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "classify_risk",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"classify_risk done in {dur:.0f}ms",
        ],
    }


async def remediate(
    state: OrphanAccountDetectorState,
) -> dict[str, Any]:
    """Execute remediate."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "remediate",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"remediate done in {dur:.0f}ms",
        ],
    }


async def report(
    state: OrphanAccountDetectorState,
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
