"""Service Dependency Mapper Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.service_dependency_mapper.models import (
    ServiceDependencyMapperState,
)
from shieldops.agents.service_dependency_mapper.tools import (
    ServiceDependencyMapperToolkit,
)

logger = structlog.get_logger()

_toolkit: ServiceDependencyMapperToolkit | None = None


def _get_toolkit() -> ServiceDependencyMapperToolkit:
    if _toolkit is None:
        return ServiceDependencyMapperToolkit()
    return _toolkit


async def discover_services(
    state: ServiceDependencyMapperState,
) -> dict[str, Any]:
    """Discover services."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.discover_services()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_services",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_services done in {dur:.0f}ms",
        ],
    }


async def trace_connections(
    state: ServiceDependencyMapperState,
) -> dict[str, Any]:
    """Trace inter-service connections."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.trace_connections()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "trace_connections",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"trace_connections done in {dur:.0f}ms",
        ],
    }


async def map_dependencies(
    state: ServiceDependencyMapperState,
) -> dict[str, Any]:
    """Map dependency graph."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.map_dependencies()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "map_dependencies",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"map_dependencies done in {dur:.0f}ms",
        ],
    }


async def detect_cycles(
    state: ServiceDependencyMapperState,
) -> dict[str, Any]:
    """Detect dependency cycles."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.detect_cycles()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "detect_cycles",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_cycles done in {dur:.0f}ms",
        ],
    }


async def assess_resilience(
    state: ServiceDependencyMapperState,
) -> dict[str, Any]:
    """Assess resilience levels."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.assess_resilience()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_resilience",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_resilience done in {dur:.0f}ms",
        ],
    }


async def report(
    state: ServiceDependencyMapperState,
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
