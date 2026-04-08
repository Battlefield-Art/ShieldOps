"""SCADA Security Analyzer Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.scada_security_analyzer.models import SCADASecurityAnalyzerState
from shieldops.agents.scada_security_analyzer.tools import SCADASecurityAnalyzerToolkit

logger = structlog.get_logger()

_toolkit: SCADASecurityAnalyzerToolkit | None = None


def _get_toolkit() -> SCADASecurityAnalyzerToolkit:
    if _toolkit is None:
        return SCADASecurityAnalyzerToolkit()
    return _toolkit


async def discover_assets(
    state: SCADASecurityAnalyzerState,
) -> dict[str, Any]:
    """Execute discover_assets."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "discover_assets",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_assets done in {duration:.0f}ms",
        ],
    }


async def analyze_traffic(
    state: SCADASecurityAnalyzerState,
) -> dict[str, Any]:
    """Execute analyze_traffic."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "analyze_traffic",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_traffic done in {duration:.0f}ms",
        ],
    }


async def detect_anomalies(
    state: SCADASecurityAnalyzerState,
) -> dict[str, Any]:
    """Execute detect_anomalies."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "detect_anomalies",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_anomalies done in {duration:.0f}ms",
        ],
    }


async def check_firmware(
    state: SCADASecurityAnalyzerState,
) -> dict[str, Any]:
    """Execute check_firmware."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "check_firmware",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_firmware done in {duration:.0f}ms",
        ],
    }


async def assess_risk(
    state: SCADASecurityAnalyzerState,
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
    state: SCADASecurityAnalyzerState,
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
