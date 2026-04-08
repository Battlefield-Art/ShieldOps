"""Industrial Protocol Analyzer Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.industrial_protocol_analyzer.models import IndustrialProtocolAnalyzerState
from shieldops.agents.industrial_protocol_analyzer.tools import IndustrialProtocolAnalyzerToolkit

logger = structlog.get_logger()

_toolkit: IndustrialProtocolAnalyzerToolkit | None = None


def _get_toolkit() -> IndustrialProtocolAnalyzerToolkit:
    if _toolkit is None:
        return IndustrialProtocolAnalyzerToolkit()
    return _toolkit


async def capture_traffic(
    state: IndustrialProtocolAnalyzerState,
) -> dict[str, Any]:
    """Execute capture_traffic."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "capture_traffic",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"capture_traffic done in {duration:.0f}ms",
        ],
    }


async def decode_protocols(
    state: IndustrialProtocolAnalyzerState,
) -> dict[str, Any]:
    """Execute decode_protocols."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "decode_protocols",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"decode_protocols done in {duration:.0f}ms",
        ],
    }


async def validate_commands(
    state: IndustrialProtocolAnalyzerState,
) -> dict[str, Any]:
    """Execute validate_commands."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "validate_commands",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"validate_commands done in {duration:.0f}ms",
        ],
    }


async def detect_anomalies(
    state: IndustrialProtocolAnalyzerState,
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


async def assess_risk(
    state: IndustrialProtocolAnalyzerState,
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
    state: IndustrialProtocolAnalyzerState,
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
