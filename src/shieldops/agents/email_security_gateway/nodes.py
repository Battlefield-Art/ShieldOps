"""Node implementations for the Email Security Gateway."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.email_security_gateway.models import (
    EmailSecurityGatewayState,
    ESGStage,
    ReasoningStep,
)
from shieldops.agents.email_security_gateway.prompts import (
    SYSTEM_ATTACHMENTS,
    SYSTEM_HEADERS,
    SYSTEM_INGEST,
    SYSTEM_QUARANTINE,
    SYSTEM_REPUTATION,
    AttachmentScanOutput,
    EmailIngestOutput,
    HeaderAnalysisOutput,
    QuarantineDecisionOutput,
    ReputationCheckOutput,
)
from shieldops.agents.email_security_gateway.tools import (
    EmailSecurityGatewayToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: EmailSecurityGatewayToolkit | None = None


def _get_toolkit() -> EmailSecurityGatewayToolkit:
    if _toolkit is None:
        return EmailSecurityGatewayToolkit()
    return _toolkit


def _step(
    state: EmailSecurityGatewayState,
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


async def ingest_email(
    state: EmailSecurityGatewayState,
) -> dict[str, Any]:
    """Ingest emails from the mail gateway."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.ingest_email(state.email_config)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "source": state.email_config.get("source", ""),
                "message_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INGEST,
            user_prompt=(f"Email ingestion context:\n{ctx}"),
            schema=EmailIngestOutput,
        )
        if hasattr(llm_result, "total_ingested"):
            logger.info(
                "llm_enhanced",
                node="ingest_email",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="ingest_email",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "ingest_email",
        f"source={state.email_config.get('source', '')}",
        f"ingested {len(raw)} emails",
        elapsed,
        "mail_server",
    )
    await toolkit.record_metric("ingested", float(len(raw)))

    return {
        "ingested_emails": raw,
        "total_ingested": len(raw),
        "stage": ESGStage.ANALYZE_HEADERS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "ingest_email",
        "session_start": start,
    }


async def analyze_headers(
    state: EmailSecurityGatewayState,
) -> dict[str, Any]:
    """Analyze email headers for authentication failures."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_headers(
        state.ingested_emails,
    )
    auth_failures = sum(
        1
        for a in analyses
        if a.get("spf_result") == "fail"
        or a.get("dkim_result") == "fail"
        or a.get("dmarc_result") == "fail"
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "email_count": len(state.ingested_emails),
                "analyses": analyses[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_HEADERS,
            user_prompt=(f"Header analysis:\n{ctx}"),
            schema=HeaderAnalysisOutput,
        )
        if hasattr(llm_result, "auth_failures") and llm_result.auth_failures > auth_failures:
            auth_failures = llm_result.auth_failures
        logger.info(
            "llm_enhanced",
            node="analyze_headers",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_headers",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "analyze_headers",
        f"analyzing {len(state.ingested_emails)} email headers",
        f"{auth_failures} auth failures",
        elapsed,
        "header_analyzer",
    )

    return {
        "header_analyses": analyses,
        "auth_failure_count": auth_failures,
        "stage": ESGStage.SCAN_ATTACHMENTS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_headers",
    }


async def scan_attachments(
    state: EmailSecurityGatewayState,
) -> dict[str, Any]:
    """Scan email attachments for malware."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scans = await toolkit.scan_attachments(
        state.ingested_emails,
    )
    malicious_count = sum(1 for s in scans if s.get("is_malicious"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "email_count": len(state.ingested_emails),
                "scan_count": len(scans),
                "malicious": malicious_count,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ATTACHMENTS,
            user_prompt=(f"Attachment scan:\n{ctx}"),
            schema=AttachmentScanOutput,
        )
        if hasattr(llm_result, "malicious_count") and llm_result.malicious_count > malicious_count:
            malicious_count = llm_result.malicious_count
        logger.info(
            "llm_enhanced",
            node="scan_attachments",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_attachments",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "scan_attachments",
        f"scanning {len(scans)} attachments",
        f"{malicious_count} malicious",
        elapsed,
        "sandbox",
    )
    await toolkit.record_metric("malicious_attachments", float(malicious_count))

    return {
        "attachment_scans": scans,
        "malicious_attachment_count": malicious_count,
        "stage": ESGStage.CHECK_REPUTATION,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "scan_attachments",
    }


async def check_reputation(
    state: EmailSecurityGatewayState,
) -> dict[str, Any]:
    """Check sender reputation against threat intel."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    reputations = await toolkit.check_sender_reputation(
        state.ingested_emails,
    )
    bad_count = sum(1 for r in reputations if r.get("is_known_bad"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "sender_count": len(reputations),
                "reputations": reputations[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPUTATION,
            user_prompt=(f"Reputation check:\n{ctx}"),
            schema=ReputationCheckOutput,
        )
        if hasattr(llm_result, "bad_senders") and llm_result.bad_senders > bad_count:
            bad_count = llm_result.bad_senders
        logger.info(
            "llm_enhanced",
            node="check_reputation",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="check_reputation",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "check_reputation",
        f"checking {len(reputations)} senders",
        f"{bad_count} bad senders",
        elapsed,
        "reputation_service",
    )

    return {
        "reputation_checks": reputations,
        "bad_sender_count": bad_count,
        "stage": ESGStage.QUARANTINE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "check_reputation",
    }


async def quarantine_messages(
    state: EmailSecurityGatewayState,
) -> dict[str, Any]:
    """Apply quarantine decisions based on all analyses."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    header_fail_ids = {
        a.get("message_id")
        for a in state.header_analyses
        if a.get("spf_result") == "fail" or a.get("dmarc_result") == "fail"
    }
    malicious_msg_ids = {
        s.get("message_id") for s in state.attachment_scans if s.get("is_malicious")
    }
    bad_senders = {r.get("sender") for r in state.reputation_checks if r.get("is_known_bad")}

    actions: list[dict[str, Any]] = []
    for email in state.ingested_emails:
        msg_id = email.get("message_id", "")
        sender = email.get("sender", "")
        if msg_id in malicious_msg_ids:
            verdict = "malware"
            confidence = 0.95
        elif msg_id in header_fail_ids and sender in bad_senders:
            verdict = "phishing"
            confidence = 0.85
        elif msg_id in header_fail_ids:
            verdict = "suspicious"
            confidence = 0.65
        elif sender in bad_senders:
            verdict = "spam"
            confidence = 0.7
        else:
            verdict = "clean"
            confidence = 0.9

        result = await toolkit.quarantine_message(
            msg_id,
            verdict,
            confidence,
        )
        actions.append(result)

    quarantined = sum(1 for a in actions if a.get("quarantined"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "total_emails": len(state.ingested_emails),
                "quarantined": quarantined,
                "actions": actions[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_QUARANTINE,
            user_prompt=(f"Quarantine decisions:\n{ctx}"),
            schema=QuarantineDecisionOutput,
        )
        if hasattr(llm_result, "quarantined"):
            logger.info(
                "llm_enhanced",
                node="quarantine_messages",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="quarantine_messages",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "quarantine_messages",
        f"evaluating {len(state.ingested_emails)} emails",
        f"quarantined {quarantined}",
        elapsed,
        "quarantine_store",
    )
    await toolkit.record_metric("quarantined", float(quarantined))

    return {
        "quarantine_actions": actions,
        "quarantined_count": quarantined,
        "stage": ESGStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "quarantine_messages",
    }


async def generate_report(
    state: EmailSecurityGatewayState,
) -> dict[str, Any]:
    """Generate final email security report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "total_ingested": state.total_ingested,
        "auth_failures": state.auth_failure_count,
        "malicious_attachments": state.malicious_attachment_count,
        "bad_senders": state.bad_sender_count,
        "quarantined": state.quarantined_count,
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("scan_duration_ms", float(duration_ms))
    await toolkit.record_metric(
        "total_processed",
        float(state.total_ingested),
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
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
