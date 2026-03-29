"""SBOM Analyzer Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.sbom_analyzer.models import SbomAnalyzerState
from shieldops.agents.sbom_analyzer.tools import SbomAnalyzerToolkit

logger = structlog.get_logger()

_toolkit: SbomAnalyzerToolkit | None = None


def set_toolkit(toolkit: SbomAnalyzerToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SbomAnalyzerToolkit:
    if _toolkit is None:
        return SbomAnalyzerToolkit()
    return _toolkit


async def parse_sbom(
    state: SbomAnalyzerState,
) -> dict[str, Any]:
    """Execute parse_sbom."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "parse_sbom",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"parse_sbom done in {dur:.0f}ms",
        ],
    }


async def match_cves(
    state: SbomAnalyzerState,
) -> dict[str, Any]:
    """Execute match_cves."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "match_cves",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"match_cves done in {dur:.0f}ms",
        ],
    }


async def check_licenses(
    state: SbomAnalyzerState,
) -> dict[str, Any]:
    """Execute check_licenses."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "check_licenses",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_licenses done in {dur:.0f}ms",
        ],
    }


async def assess_risk(
    state: SbomAnalyzerState,
) -> dict[str, Any]:
    """Execute assess_risk."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_risk",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_risk done in {dur:.0f}ms",
        ],
    }


async def prioritize(
    state: SbomAnalyzerState,
) -> dict[str, Any]:
    """Execute prioritize."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "prioritize",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"prioritize done in {dur:.0f}ms",
        ],
    }


async def report(
    state: SbomAnalyzerState,
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
