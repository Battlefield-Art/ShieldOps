"""Configuration Auditor Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.configuration_auditor.models import (
    ConfigurationAuditorState,
)
from shieldops.agents.configuration_auditor.tools import (
    ConfigurationAuditorToolkit,
)

logger = structlog.get_logger()

_toolkit: ConfigurationAuditorToolkit | None = None


def _get_toolkit() -> ConfigurationAuditorToolkit:
    if _toolkit is None:
        return ConfigurationAuditorToolkit()
    return _toolkit


async def collect_configs(
    state: ConfigurationAuditorState,
) -> dict[str, Any]:
    """Execute collect_configs."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.collect_configs()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_configs",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_configs done in {dur:.0f}ms",
        ],
    }


async def parse_settings(
    state: ConfigurationAuditorState,
) -> dict[str, Any]:
    """Execute parse_settings."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.parse_settings()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "parse_settings",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"parse_settings done in {dur:.0f}ms",
        ],
    }


async def validate_security(
    state: ConfigurationAuditorState,
) -> dict[str, Any]:
    """Execute validate_security."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.validate_security()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "validate_security",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"validate_security done in {dur:.0f}ms"),
        ],
    }


async def detect_drift(
    state: ConfigurationAuditorState,
) -> dict[str, Any]:
    """Execute detect_drift."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.detect_drift()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "detect_drift",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_drift done in {dur:.0f}ms",
        ],
    }


async def recommend_fixes(
    state: ConfigurationAuditorState,
) -> dict[str, Any]:
    """Execute recommend_fixes."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.recommend_fixes()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "recommend_fixes",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"recommend_fixes done in {dur:.0f}ms",
        ],
    }


async def report(
    state: ConfigurationAuditorState,
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
