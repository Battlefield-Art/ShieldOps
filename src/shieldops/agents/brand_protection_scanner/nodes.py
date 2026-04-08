"""Brand Protection Scanner Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.brand_protection_scanner.models import BrandProtectionScannerState
from shieldops.agents.brand_protection_scanner.tools import BrandProtectionScannerToolkit

logger = structlog.get_logger()

_toolkit: BrandProtectionScannerToolkit | None = None


def _get_toolkit() -> BrandProtectionScannerToolkit:
    if _toolkit is None:
        return BrandProtectionScannerToolkit()
    return _toolkit


async def discover_domains(
    state: BrandProtectionScannerState,
) -> dict[str, Any]:
    """Execute discover_domains."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_domains",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_domains done in {dur:.0f}ms",
        ],
    }


async def analyze_similarity(
    state: BrandProtectionScannerState,
) -> dict[str, Any]:
    """Execute analyze_similarity."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_similarity",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_similarity done in {dur:.0f}ms",
        ],
    }


async def check_certificates(
    state: BrandProtectionScannerState,
) -> dict[str, Any]:
    """Execute check_certificates."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "check_certificates",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_certificates done in {dur:.0f}ms",
        ],
    }


async def classify_threats(
    state: BrandProtectionScannerState,
) -> dict[str, Any]:
    """Execute classify_threats."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "classify_threats",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"classify_threats done in {dur:.0f}ms",
        ],
    }


async def takedown(
    state: BrandProtectionScannerState,
) -> dict[str, Any]:
    """Execute takedown."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "takedown",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"takedown done in {dur:.0f}ms",
        ],
    }


async def report(
    state: BrandProtectionScannerState,
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
