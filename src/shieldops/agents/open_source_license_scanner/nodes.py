"""Open Source License Scanner Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.open_source_license_scanner.models import OpenSourceLicenseScannerState
from shieldops.agents.open_source_license_scanner.tools import OpenSourceLicenseScannerToolkit

logger = structlog.get_logger()

_toolkit: OpenSourceLicenseScannerToolkit | None = None


def set_toolkit(toolkit: OpenSourceLicenseScannerToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> OpenSourceLicenseScannerToolkit:
    if _toolkit is None:
        return OpenSourceLicenseScannerToolkit()
    return _toolkit


async def discover_deps(
    state: OpenSourceLicenseScannerState,
) -> dict[str, Any]:
    """Execute discover_deps."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_deps",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_deps done in {dur:.0f}ms",
        ],
    }


async def identify_licenses(
    state: OpenSourceLicenseScannerState,
) -> dict[str, Any]:
    """Execute identify_licenses."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "identify_licenses",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_licenses done in {dur:.0f}ms",
        ],
    }


async def check_compatibility(
    state: OpenSourceLicenseScannerState,
) -> dict[str, Any]:
    """Execute check_compatibility."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "check_compatibility",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_compatibility done in {dur:.0f}ms",
        ],
    }


async def flag_violations(
    state: OpenSourceLicenseScannerState,
) -> dict[str, Any]:
    """Execute flag_violations."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "flag_violations",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"flag_violations done in {dur:.0f}ms",
        ],
    }


async def recommend(
    state: OpenSourceLicenseScannerState,
) -> dict[str, Any]:
    """Execute recommend."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "recommend",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"recommend done in {dur:.0f}ms",
        ],
    }


async def report(
    state: OpenSourceLicenseScannerState,
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
