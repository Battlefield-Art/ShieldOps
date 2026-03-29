"""Browser Isolation Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import IsolationStage
from .prompts import (
    SYSTEM_BREAKOUT,
    SYSTEM_REPORT,
    BreakoutAnalysisResult,
    IsolationReportResult,
)
from .tools import BrowserIsolationToolkit

logger = structlog.get_logger()

_toolkit: BrowserIsolationToolkit | None = None


def set_toolkit(tk: BrowserIsolationToolkit) -> None:
    global _toolkit
    _toolkit = tk


async def collect_sessions(
    state: dict[str, Any], toolkit: BrowserIsolationToolkit
) -> dict[str, Any]:
    """Collect active browser sessions."""
    logger.info("bi.node.collect")
    tenant_id = state.get("tenant_id", "")
    sessions = await toolkit.collect_sessions(tenant_id)
    isolated = sum(1 for s in sessions if s.get("isolated", False))
    return {
        "stage": IsolationStage.DETECT_BREAKOUTS.value,
        "sessions": sessions,
        "total_sessions": len(sessions),
        "active_isolated": isolated,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(sessions)} sessions, {isolated} isolated"],
    }


async def detect_breakouts(
    state: dict[str, Any], toolkit: BrowserIsolationToolkit
) -> dict[str, Any]:
    """Detect breakout attempts."""
    logger.info("bi.node.breakout")
    sessions = state.get("sessions", [])
    attempts, blocked = await toolkit.detect_breakouts(sessions)

    reasoning = f"Detected {len(attempts)} breakout attempts, {blocked} blocked"

    if attempts:
        try:
            ctx = json.dumps(
                {"attempts": attempts[:10], "blocked": blocked},
                default=str,
            )
            result = cast(
                BreakoutAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_BREAKOUT,
                    user_prompt=f"Breakout analysis:\n{ctx}",
                    schema=BreakoutAnalysisResult,
                ),
            )
            reasoning = f"{result.summary}. {reasoning}"
        except Exception:
            logger.debug("llm_fallback", agent="bi", node="breakout")

    return {
        "stage": IsolationStage.EVALUATE_POLICIES.value,
        "breakout_attempts": attempts,
        "breakouts_blocked": blocked,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def evaluate_policies(
    state: dict[str, Any], toolkit: BrowserIsolationToolkit
) -> dict[str, Any]:
    """Evaluate isolation policies."""
    logger.info("bi.node.policies")
    sessions = state.get("sessions", [])
    violations, enforced = await toolkit.evaluate_policies(sessions)
    return {
        "stage": IsolationStage.SANDBOX_CONTENT.value,
        "policy_violations": violations,
        "policies_enforced": enforced,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"{len(violations)} policy violations, {enforced} enforced"],
    }


async def sandbox_content(
    state: dict[str, Any], toolkit: BrowserIsolationToolkit
) -> dict[str, Any]:
    """Sandbox suspicious web content."""
    logger.info("bi.node.sandbox")
    sessions = state.get("sessions", [])
    sandboxed = await toolkit.sandbox_content(sessions)
    return {
        "stage": IsolationStage.REPORT.value,
        "sandboxed_content": sandboxed,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Sandboxed {len(sandboxed)} content items"],
    }


async def generate_report(
    state: dict[str, Any], toolkit: BrowserIsolationToolkit
) -> dict[str, Any]:
    """Generate browser isolation report."""
    logger.info("bi.node.report")
    total = state.get("total_sessions", 0)
    isolated = state.get("active_isolated", 0)
    blocked = state.get("breakouts_blocked", 0)
    risk = min(
        len(state.get("breakout_attempts", [])) * 15.0
        + len(state.get("policy_violations", [])) * 10.0,
        100.0,
    )

    summary = (
        f"Browser isolation: {total} sessions, {isolated} isolated, "
        f"{blocked} breakouts blocked, risk={risk:.1f}"
    )

    try:
        ctx = json.dumps(
            {
                "total_sessions": total,
                "isolated": isolated,
                "breakouts_blocked": blocked,
                "policy_violations": len(state.get("policy_violations", [])),
                "sandboxed": len(state.get("sandboxed_content", [])),
            },
            default=str,
        )
        result = cast(
            IsolationReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Isolation report:\n{ctx}",
                schema=IsolationReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("llm_fallback", agent="bi", node="report")

    return {
        "stage": IsolationStage.REPORT.value,
        "summary": summary,
        "risk_score": risk,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
