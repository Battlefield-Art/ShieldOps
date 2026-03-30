"""API Gateway Security Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.api_gateway_security.models import (
    APIGatewaySecurityState,
)
from shieldops.agents.api_gateway_security.tools import (
    APIGatewaySecurityToolkit,
)

logger = structlog.get_logger()

_toolkit: APIGatewaySecurityToolkit | None = None


def set_toolkit(
    toolkit: APIGatewaySecurityToolkit,
) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> APIGatewaySecurityToolkit:
    if _toolkit is None:
        return APIGatewaySecurityToolkit()
    return _toolkit


async def scan_endpoints(
    state: APIGatewaySecurityState,
) -> dict[str, Any]:
    """Execute scan_endpoints."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.scan_endpoints()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "scan_endpoints",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"scan_endpoints done in {dur:.0f}ms",
        ],
    }


async def analyze_traffic(
    state: APIGatewaySecurityState,
) -> dict[str, Any]:
    """Execute analyze_traffic."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.analyze_traffic()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_traffic",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_traffic done in {dur:.0f}ms",
        ],
    }


async def detect_abuse(
    state: APIGatewaySecurityState,
) -> dict[str, Any]:
    """Execute detect_abuse."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.detect_abuse()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "detect_abuse",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_abuse done in {dur:.0f}ms",
        ],
    }


async def enforce_policies(
    state: APIGatewaySecurityState,
) -> dict[str, Any]:
    """Execute enforce_policies."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.enforce_policies()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "enforce_policies",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"enforce_policies done in {dur:.0f}ms",
        ],
    }


async def generate_alerts(
    state: APIGatewaySecurityState,
) -> dict[str, Any]:
    """Execute generate_alerts."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.generate_alerts()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "generate_alerts",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"generate_alerts done in {dur:.0f}ms",
        ],
    }


async def report(
    state: APIGatewaySecurityState,
) -> dict[str, Any]:
    """Generate final report."""
    return {
        "current_step": "report",
        "stats": {
            "total_findings": len(state.findings),
            "steps": len(state.reasoning_chain),
        },
        "reasoning_chain": [
            *state.reasoning_chain,
            "report generated",
        ],
    }
