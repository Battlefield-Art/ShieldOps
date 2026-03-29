"""Email DLP Monitor Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import DLPStage, DLPViolation, EmailScan
from .tools import EmailDLPMonitorToolkit

logger = structlog.get_logger()

_toolkit: EmailDLPMonitorToolkit | None = None


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def scan_outbound(
    state: dict[str, Any],
    toolkit: EmailDLPMonitorToolkit,
) -> dict[str, Any]:
    """Scan outbound emails."""
    logger.info("email_dlp.node.scan_outbound")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")

    scans = await toolkit.scan_outbound(tenant_id)

    return {
        "outbound_scans": [s.model_dump() for s in scans],
        "emails_scanned": len(scans),
        "stage": DLPStage.SCAN_OUTBOUND.value,
        "session_start": time.time(),
        "current_step": "scan_outbound",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Scanned {len(scans)} outbound emails"],
    }


async def detect_pii(
    state: dict[str, Any],
    toolkit: EmailDLPMonitorToolkit,
) -> dict[str, Any]:
    """Detect PII in emails."""
    logger.info("email_dlp.node.detect_pii")
    state = _to_dict(state)
    raw_scans = state.get("outbound_scans", [])

    scans = [EmailScan(**s) if isinstance(s, dict) else s for s in raw_scans]
    detections, count = await toolkit.detect_pii(scans)

    reasoning_note = f"Detected {count} PII instances"

    try:
        from .prompts import (
            SYSTEM_PII_DETECTION,
            PIIDetectionOutput,
        )

        context = json.dumps(
            {
                "detections": detections[:20],
                "count": count,
            },
            default=str,
        )
        llm_out = cast(
            PIIDetectionOutput,
            await llm_structured(
                system_prompt=SYSTEM_PII_DETECTION,
                user_prompt=(f"PII detection results:\n{context}"),
                schema=PIIDetectionOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="email_dlp_monitor",
            node="detect_pii",
        )
        reasoning_note = f"{llm_out.summary} [risk={llm_out.risk_level}]"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="email_dlp_monitor",
            node="detect_pii",
        )

    return {
        "pii_detections": detections,
        "pii_count": count,
        "stage": DLPStage.DETECT_PII.value,
        "current_step": "detect_pii",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def analyze_attachments(
    state: dict[str, Any],
    toolkit: EmailDLPMonitorToolkit,
) -> dict[str, Any]:
    """Analyze email attachments."""
    logger.info("email_dlp.node.analyze_attachments")
    state = _to_dict(state)
    raw_scans = state.get("outbound_scans", [])

    scans = [EmailScan(**s) if isinstance(s, dict) else s for s in raw_scans]
    results, risky = await toolkit.analyze_attachments(scans)

    return {
        "attachment_scans": results,
        "risky_attachments": risky,
        "stage": DLPStage.ANALYZE_ATTACHMENTS.value,
        "current_step": "analyze_attachments",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Attachment scan: {len(results)} files, {risky} risky"],
    }


async def enforce_policy(
    state: dict[str, Any],
    toolkit: EmailDLPMonitorToolkit,
) -> dict[str, Any]:
    """Enforce DLP policies."""
    logger.info("email_dlp.node.enforce_policy")
    state = _to_dict(state)
    pii = state.get("pii_detections", [])
    attachments = state.get("attachment_scans", [])

    violations, blocked = await toolkit.enforce_policy(
        pii,
        attachments,
    )

    reasoning_note = f"Enforced policies: {len(violations)} violations, {blocked} blocked"

    try:
        from .prompts import (
            SYSTEM_POLICY_ENFORCEMENT,
            PolicyEnforcementOutput,
        )

        context = json.dumps(
            {
                "violations": [v.model_dump() for v in violations[:20]],
                "blocked": blocked,
            },
            default=str,
        )
        llm_out = cast(
            PolicyEnforcementOutput,
            await llm_structured(
                system_prompt=SYSTEM_POLICY_ENFORCEMENT,
                user_prompt=(f"Policy enforcement:\n{context}"),
                schema=PolicyEnforcementOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="email_dlp_monitor",
            node="enforce_policy",
        )
        reasoning_note = f"{llm_out.summary} [action={llm_out.action}]"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="email_dlp_monitor",
            node="enforce_policy",
        )

    return {
        "violations": [v.model_dump() for v in violations],
        "violations_count": len(violations),
        "blocked_count": blocked,
        "stage": DLPStage.ENFORCE_POLICY.value,
        "current_step": "enforce_policy",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def audit_log(
    state: dict[str, Any],
    toolkit: EmailDLPMonitorToolkit,
) -> dict[str, Any]:
    """Create audit log entries."""
    logger.info("email_dlp.node.audit_log")
    state = _to_dict(state)
    raw_violations = state.get("violations", [])

    violations = [DLPViolation(**v) if isinstance(v, dict) else v for v in raw_violations]
    entries = await toolkit.audit_log(violations)

    return {
        "audit_entries": entries,
        "stage": DLPStage.AUDIT_LOG.value,
        "current_step": "audit_log",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Audit log: {len(entries)} entries created"],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: EmailDLPMonitorToolkit,
) -> dict[str, Any]:
    """Generate final DLP report."""
    logger.info("email_dlp.node.generate_report")
    state = _to_dict(state)

    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    stats = {
        "emails_scanned": state.get("emails_scanned", 0),
        "pii_count": state.get("pii_count", 0),
        "risky_attachments": state.get("risky_attachments", 0),
        "violations_count": state.get("violations_count", 0),
        "blocked_count": state.get("blocked_count", 0),
        "audit_entries": len(state.get("audit_entries", [])),
        "analysis_duration_ms": round(duration_ms, 2),
    }

    return {
        "stats": stats,
        "stage": DLPStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Report: {stats['emails_scanned']} scanned, {stats['blocked_count']} blocked"],
    }
