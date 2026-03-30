"""Node implementations for the Browser Threat Protector."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.browser_threat_protector.models import (
    BrowserThreatProtectorState,
    BTPStage,
    ReasoningStep,
)
from shieldops.agents.browser_threat_protector.prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_ENFORCE,
    SYSTEM_ISOLATE,
    SYSTEM_REPUTATION,
    SYSTEM_SCAN,
    ContentScanOutput,
    IsolationOutput,
    PolicyEnforcementOutput,
    ReputationCheckOutput,
    RequestAnalysisOutput,
)
from shieldops.agents.browser_threat_protector.tools import (
    BrowserThreatProtectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: BrowserThreatProtectorToolkit | None = None


def set_toolkit(
    toolkit: BrowserThreatProtectorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> BrowserThreatProtectorToolkit:
    if _toolkit is None:
        return BrowserThreatProtectorToolkit()
    return _toolkit


def _step(
    state: BrowserThreatProtectorState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Create a reasoning step."""
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def analyze_request(
    state: BrowserThreatProtectorState,
) -> dict[str, Any]:
    """Analyze incoming web requests."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.analyze_request(
        state.protection_config,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "request_count": len(raw),
                "urls": [r.get("url", "") for r in raw[:10]],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=(f"Request analysis context:\n{ctx}"),
            schema=RequestAnalysisOutput,
        )
        if hasattr(llm_result, "suspicious_count"):
            logger.info(
                "llm_enhanced",
                node="analyze_request",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_request",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "analyze_request",
        f"config={state.protection_config.get('mode', '')}",
        f"analyzed {len(raw)} requests",
        elapsed,
        "request_analyzer",
    )
    await toolkit.record_metric(
        "requests_analyzed",
        float(len(raw)),
    )

    return {
        "web_requests": raw,
        "request_count": len(raw),
        "stage": BTPStage.CHECK_REPUTATION,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_request",
        "session_start": start,
    }


async def check_reputation(
    state: BrowserThreatProtectorState,
) -> dict[str, Any]:
    """Check URL reputation against threat feeds."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.check_url_reputation(
        state.web_requests,
    )
    suspicious = sum(1 for r in results if r.get("reputation") in ("suspicious", "malicious"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "request_count": len(state.web_requests),
                "results": results[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPUTATION,
            user_prompt=(f"Reputation check context:\n{ctx}"),
            schema=ReputationCheckOutput,
        )
        if hasattr(llm_result, "suspicious_count") and llm_result.suspicious_count > suspicious:
            suspicious = llm_result.suspicious_count
        logger.info(
            "llm_enhanced",
            node="check_reputation",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="check_reputation",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "check_reputation",
        f"checking {len(state.web_requests)} URLs",
        f"{suspicious} suspicious URLs found",
        elapsed,
        "url_reputation",
    )

    return {
        "reputation_results": results,
        "suspicious_count": suspicious,
        "stage": BTPStage.ISOLATE_SESSION,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "check_reputation",
    }


async def isolate_session(
    state: BrowserThreatProtectorState,
) -> dict[str, Any]:
    """Isolate suspicious browser sessions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sessions = await toolkit.isolate_session(
        state.web_requests,
        state.reputation_results,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "suspicious_count": state.suspicious_count,
                "sessions": sessions[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ISOLATE,
            user_prompt=(f"Isolation context:\n{ctx}"),
            schema=IsolationOutput,
        )
        if hasattr(llm_result, "isolated_count"):
            logger.info(
                "llm_enhanced",
                node="isolate_session",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="isolate_session",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "isolate_session",
        f"isolating {state.suspicious_count} suspicious",
        f"created {len(sessions)} isolation sessions",
        elapsed,
        "isolation_engine",
    )
    await toolkit.record_metric(
        "isolated_sessions",
        float(len(sessions)),
    )

    return {
        "isolation_sessions": sessions,
        "isolated_count": len(sessions),
        "stage": BTPStage.SCAN_CONTENT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "isolate_session",
    }


async def scan_content(
    state: BrowserThreatProtectorState,
) -> dict[str, Any]:
    """Scan content from isolated sessions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.scan_content(
        state.isolation_sessions,
    )
    threats = sum(1 for r in results if r.get("threats_found"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "session_count": len(state.isolation_sessions),
                "results": results[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SCAN,
            user_prompt=(f"Content scan context:\n{ctx}"),
            schema=ContentScanOutput,
        )
        if hasattr(llm_result, "threats_found") and llm_result.threats_found > threats:
            threats = llm_result.threats_found
        logger.info(
            "llm_enhanced",
            node="scan_content",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_content",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "scan_content",
        f"scanning {len(state.isolation_sessions)} sessions",
        f"found {threats} threats",
        elapsed,
        "content_scanner",
    )
    await toolkit.record_metric(
        "threats_found",
        float(threats),
    )

    return {
        "scan_results": results,
        "threats_found": threats,
        "stage": BTPStage.ENFORCE_POLICY,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "scan_content",
    }


async def enforce_policy(
    state: BrowserThreatProtectorState,
) -> dict[str, Any]:
    """Enforce security policies based on results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.enforce_policy(
        state.web_requests,
        state.scan_results,
    )
    blocked = sum(1 for a in actions if a.get("action") == "block")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "threats_found": state.threats_found,
                "actions": actions[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ENFORCE,
            user_prompt=(f"Policy enforcement context:\n{ctx}"),
            schema=PolicyEnforcementOutput,
        )
        if hasattr(llm_result, "blocked"):
            logger.info(
                "llm_enhanced",
                node="enforce_policy",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enforce_policy",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "enforce_policy",
        f"enforcing on {len(state.web_requests)} requests",
        f"blocked {blocked} requests",
        elapsed,
        "policy_engine",
    )

    return {
        "policy_actions": actions,
        "blocked_count": blocked,
        "stage": BTPStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "enforce_policy",
    }


async def generate_report(
    state: BrowserThreatProtectorState,
) -> dict[str, Any]:
    """Generate final browser threat protection report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "total_requests": state.request_count,
        "suspicious_urls": state.suspicious_count,
        "isolated_sessions": state.isolated_count,
        "threats_found": state.threats_found,
        "blocked_count": state.blocked_count,
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "generate_report",
        f"finalizing scan {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
