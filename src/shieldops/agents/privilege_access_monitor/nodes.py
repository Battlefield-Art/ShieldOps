"""Node implementations for the Privilege Access Monitor
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.privilege_access_monitor.models import (
    PAMStage,
    PrivilegeAccessMonitorState,
    ReasoningStep,
)
from shieldops.agents.privilege_access_monitor.prompts import (
    SYSTEM_ABUSE,
    SYSTEM_JIT,
    SYSTEM_REPORT,
    SYSTEM_RISK,
    AbuseDetectionOutput,
    JITDecisionOutput,
    PAMReportOutput,
    RiskAssessmentOutput,
)
from shieldops.agents.privilege_access_monitor.tools import (
    PrivilegeAccessMonitorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: PrivilegeAccessMonitorToolkit | None = None


def _get_toolkit() -> PrivilegeAccessMonitorToolkit:
    if _toolkit is None:
        return PrivilegeAccessMonitorToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: datetime,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: discover_accounts
# ------------------------------------------------------------------


async def discover_accounts(
    state: PrivilegeAccessMonitorState,
) -> dict[str, Any]:
    """Discover privileged accounts across platforms."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    accounts = await toolkit.discover_accounts(
        platforms=state.target_platforms,
        scope=state.scope,
    )

    step = _step(
        state.reasoning_chain,
        "discover_accounts",
        (f"Platforms: {len(state.target_platforms)}"),
        f"Discovered {len(accounts)} accounts",
        start,
        "pam_connector",
    )

    return {
        "accounts": accounts,
        "total_accounts": len(accounts),
        "stage": PAMStage.DISCOVER_ACCOUNTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "discover_accounts",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: audit_sessions
# ------------------------------------------------------------------


async def audit_sessions(
    state: PrivilegeAccessMonitorState,
) -> dict[str, Any]:
    """Audit privileged sessions for suspicious activity."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sessions = await toolkit.audit_sessions(
        accounts=state.accounts,
        window_hours=state.audit_window_hours,
    )

    step = _step(
        state.reasoning_chain,
        "audit_sessions",
        (f"Auditing {len(state.accounts)} accounts, window={state.audit_window_hours}h"),
        f"Audited {len(sessions)} sessions",
        start,
        "session_recorder",
    )

    return {
        "sessions": sessions,
        "stage": PAMStage.AUDIT_SESSIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "audit_sessions",
    }


# ------------------------------------------------------------------
# Node: detect_abuse
# ------------------------------------------------------------------


async def detect_abuse(
    state: PrivilegeAccessMonitorState,
) -> dict[str, Any]:
    """Detect privileged access abuse patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    detections = await toolkit.detect_abuse(
        sessions=state.sessions,
        accounts=state.accounts,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "sessions": state.sessions[:5],
                "accounts": state.accounts[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ABUSE,
            user_prompt=f"Detect abuse:\n{ctx}",
            schema=AbuseDetectionOutput,
        )
        if llm_out.abuse_detected:  # type: ignore[union-attr]
            detections.append(
                {
                    "detection_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "indicator": llm_out.indicator,  # type: ignore[union-attr]
                    "severity": llm_out.severity,  # type: ignore[union-attr]
                    "confidence": llm_out.confidence,  # type: ignore[union-attr]
                    "evidence": llm_out.evidence,  # type: ignore[union-attr]
                    "recommended_action": llm_out.recommended_action,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="detect_abuse",
            detected=llm_out.abuse_detected,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_abuse",
        )

    step = _step(
        state.reasoning_chain,
        "detect_abuse",
        (f"Analyzing {len(state.sessions)} sessions"),
        f"Detected {len(detections)} abuse events",
        start,
        "abuse_detector",
    )

    return {
        "detections": detections,
        "abuse_detected": len(detections),
        "stage": PAMStage.DETECT_ABUSE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_abuse",
    }


# ------------------------------------------------------------------
# Node: assess_risk
# ------------------------------------------------------------------


async def assess_risk(
    state: PrivilegeAccessMonitorState,
) -> dict[str, Any]:
    """Assess risk for discovered privileged accounts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments: list[dict[str, Any]] = []
    high_risk = 0

    for account in state.accounts:
        assessment = await toolkit.assess_risk(
            account=account,
            sessions=state.sessions,
            detections=state.detections,
        )

        # LLM enhancement
        try:
            ctx = _json.dumps(
                {
                    "account": account,
                    "detections": state.detections[:5],
                },
                default=str,
            )
            llm_out = await llm_structured(
                system_prompt=SYSTEM_RISK,
                user_prompt=f"Assess risk:\n{ctx}",
                schema=RiskAssessmentOutput,
            )
            assessment = {
                "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                "risk_factors": llm_out.risk_factors,  # type: ignore[union-attr]
                "jit_eligible": llm_out.jit_eligible,  # type: ignore[union-attr]
                "recommendation": llm_out.recommendation,  # type: ignore[union-attr]
            }
            logger.info(
                "llm_enhanced",
                node="assess_risk",
                risk_score=llm_out.risk_score,  # type: ignore[union-attr]
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="assess_risk",
            )

        assessments.append(assessment)
        if assessment.get("risk_score", 0) >= 7.0:
            high_risk += 1

    step = _step(
        state.reasoning_chain,
        "assess_risk",
        f"Assessing {len(state.accounts)} accounts",
        (f"{high_risk} high-risk of {len(assessments)} assessed"),
        start,
        "risk_scorer",
    )

    return {
        "risk_assessments": assessments,
        "high_risk_count": high_risk,
        "stage": PAMStage.ASSESS_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_risk",
    }


# ------------------------------------------------------------------
# Node: enforce_jit
# ------------------------------------------------------------------


async def enforce_jit(
    state: PrivilegeAccessMonitorState,
) -> dict[str, Any]:
    """Enforce JIT access on eligible accounts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    enforcements: list[dict[str, Any]] = []

    for i, assessment in enumerate(state.risk_assessments):
        if not assessment.get("jit_eligible", False):
            continue

        account = state.accounts[i] if i < len(state.accounts) else {}

        # LLM decision
        try:
            ctx = _json.dumps(
                {
                    "account": account,
                    "assessment": assessment,
                },
                default=str,
            )
            llm_out = await llm_structured(
                system_prompt=SYSTEM_JIT,
                user_prompt=f"JIT decision:\n{ctx}",
                schema=JITDecisionOutput,
            )
            if llm_out.enforce_jit:  # type: ignore[union-attr]
                result = await toolkit.enforce_jit_access(
                    account=account,
                    assessment=assessment,
                )
                result["ttl_minutes"] = llm_out.ttl_minutes  # type: ignore[union-attr]
                result["justification"] = llm_out.justification  # type: ignore[union-attr]
                enforcements.append(result)
            logger.info(
                "llm_enhanced",
                node="enforce_jit",
                enforce=llm_out.enforce_jit,  # type: ignore[union-attr]
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="enforce_jit",
            )

    step = _step(
        state.reasoning_chain,
        "enforce_jit",
        (f"Evaluating {len(state.risk_assessments)} assessments"),
        f"Enforced JIT on {len(enforcements)} accounts",
        start,
        "jit_engine",
    )

    return {
        "jit_enforcements": enforcements,
        "jit_enforced": len(enforcements),
        "stage": PAMStage.ENFORCE_JIT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enforce_jit",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: PrivilegeAccessMonitorState,
) -> dict[str, Any]:
    """Generate the final PAM audit report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    report: dict[str, Any] = {
        "total_accounts": state.total_accounts,
        "abuse_detected": state.abuse_detected,
        "high_risk_count": state.high_risk_count,
        "jit_enforced": state.jit_enforced,
        "duration_ms": duration_ms,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "total_accounts": state.total_accounts,
                "abuse_detected": state.abuse_detected,
                "high_risk_count": state.high_risk_count,
                "jit_enforced": state.jit_enforced,
                "detections": state.detections[:5],
                "risk_assessments": (state.risk_assessments[:5]),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate PAM report:\n{ctx}",
            schema=PAMReportOutput,
        )
        if isinstance(llm_out, PAMReportOutput):
            report.update(
                {
                    "executive_summary": (llm_out.executive_summary),
                    "high_risk_accounts": (llm_out.high_risk_accounts),
                    "recommendations": (llm_out.recommendations),
                    "compliance_status": (llm_out.compliance_status),
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recommendations=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    await toolkit.record_metric(
        metric_name="pam_audit_duration_ms",
        value=float(duration_ms),
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_accounts} accounts"),
        "PAM report generated",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": PAMStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
