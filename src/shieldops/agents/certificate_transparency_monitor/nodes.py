"""Node implementations for the Certificate Transparency
Monitor Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.certificate_transparency_monitor.models import (
    CertificateTransparencyMonitorState,
    CTMStage,
    ReasoningStep,
)
from shieldops.agents.certificate_transparency_monitor.prompts import (
    SYSTEM_ANOMALY,
    SYSTEM_OWNERSHIP,
    SYSTEM_REPORT,
    AnomalyDetectionOutput,
    CTReportOutput,
    OwnershipVerificationOutput,
)
from shieldops.agents.certificate_transparency_monitor.tools import (
    CertificateTransparencyMonitorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CertificateTransparencyMonitorToolkit | None = None


def _get_toolkit() -> CertificateTransparencyMonitorToolkit:
    if _toolkit is None:
        return CertificateTransparencyMonitorToolkit()
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
# Node: monitor_logs
# ------------------------------------------------------------------


async def monitor_logs(
    state: CertificateTransparencyMonitorState,
) -> dict[str, Any]:
    """Query CT logs for certificates matching watched
    domains."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    entries = await toolkit.monitor_logs(
        watched_domains=state.watched_domains,
        ct_log_sources=state.ct_log_sources,
    )

    step = _step(
        state.reasoning_chain,
        "monitor_logs",
        f"Watching {len(state.watched_domains)} domains",
        f"Found {len(entries)} CT log entries",
        start,
        "ct_client",
    )

    return {
        "log_entries": entries,
        "stage": CTMStage.MONITOR_LOGS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "monitor_logs",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: parse_certificates
# ------------------------------------------------------------------


async def parse_certificates(
    state: CertificateTransparencyMonitorState,
) -> dict[str, Any]:
    """Parse raw CT log entries into structured cert data."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    parsed = await toolkit.parse_certificates(
        log_entries=state.log_entries,
    )

    step = _step(
        state.reasoning_chain,
        "parse_certificates",
        f"Parsing {len(state.log_entries)} log entries",
        f"Parsed {len(parsed)} certificates",
        start,
        "cert_parser",
    )

    return {
        "parsed_certs": parsed,
        "total_certs_scanned": len(parsed),
        "stage": CTMStage.PARSE_CERTIFICATES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "parse_certificates",
    }


# ------------------------------------------------------------------
# Node: detect_anomalies
# ------------------------------------------------------------------


async def detect_anomalies(
    state: CertificateTransparencyMonitorState,
) -> dict[str, Any]:
    """Detect anomalies in certificate issuance patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    anomalies = await toolkit.detect_anomalies(
        parsed_certs=state.parsed_certs,
        watched_domains=state.watched_domains,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "watched_domains": state.watched_domains,
                "cert_count": len(state.parsed_certs),
                "certs_sample": state.parsed_certs[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANOMALY,
            user_prompt=f"Detect CT anomalies:\n{ctx}",
            schema=AnomalyDetectionOutput,
        )
        if llm_out.anomalies:  # type: ignore[union-attr]
            anomalies = [
                *anomalies,
                *llm_out.anomalies,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="detect_anomalies",
            count=len(llm_out.anomalies),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_anomalies",
        )

    impersonations = sum(
        1 for a in anomalies if isinstance(a, dict) and a.get("type") == "domain_impersonation"
    )

    step = _step(
        state.reasoning_chain,
        "detect_anomalies",
        f"Analyzing {len(state.parsed_certs)} certs",
        f"Found {len(anomalies)} anomalies",
        start,
        "anomaly_detector",
    )

    return {
        "anomalies": anomalies,
        "anomalies_found": len(anomalies),
        "impersonation_attempts": impersonations,
        "stage": CTMStage.DETECT_ANOMALIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_anomalies",
    }


# ------------------------------------------------------------------
# Node: check_ownership
# ------------------------------------------------------------------


async def check_ownership(
    state: CertificateTransparencyMonitorState,
) -> dict[str, Any]:
    """Verify domain ownership for anomalous certificates."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    ownership_results: list[dict[str, Any]] = []

    for anomaly in state.anomalies:
        domain = anomaly.get("domain", "") if isinstance(anomaly, dict) else ""
        if not domain:
            continue

        result = await toolkit.check_ownership(
            domain=domain,
            watched_domains=state.watched_domains,
        )

        # LLM enhancement per domain
        try:
            ctx = _json.dumps(
                {
                    "domain": domain,
                    "anomaly": anomaly,
                    "watched_domains": state.watched_domains,
                },
                default=str,
            )
            llm_out = await llm_structured(
                system_prompt=SYSTEM_OWNERSHIP,
                user_prompt=f"Verify ownership:\n{ctx}",
                schema=OwnershipVerificationOutput,
            )
            _rid = random.randint(1000, 9999)  # noqa: S311
            result = {
                "check_id": f"llm-{_rid}",
                "domain": domain,
                "owned": llm_out.likely_owned,  # type: ignore[union-attr]
                "evidence": llm_out.evidence,  # type: ignore[union-attr]
                "risk_level": llm_out.risk_level,  # type: ignore[union-attr]
            }
            logger.info(
                "llm_enhanced",
                node="check_ownership",
                domain=domain,
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="check_ownership",
            )

        ownership_results.append(result)

    step = _step(
        state.reasoning_chain,
        "check_ownership",
        f"Checking {len(state.anomalies)} domains",
        f"Verified {len(ownership_results)} domains",
        start,
        "ownership_checker",
    )

    return {
        "ownership_results": ownership_results,
        "stage": CTMStage.CHECK_OWNERSHIP,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "check_ownership",
    }


# ------------------------------------------------------------------
# Node: send_alerts
# ------------------------------------------------------------------


async def send_alerts(
    state: CertificateTransparencyMonitorState,
) -> dict[str, Any]:
    """Send alerts for confirmed anomalies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    alerts = await toolkit.send_alerts(
        anomalies=state.anomalies,
        ownership_results=state.ownership_results,
    )

    step = _step(
        state.reasoning_chain,
        "send_alerts",
        f"Alerting on {len(state.anomalies)} anomalies",
        f"Sent {len(alerts)} alerts",
        start,
        "alert_manager",
    )

    return {
        "alerts": alerts,
        "alerts_sent": len(alerts),
        "stage": CTMStage.ALERT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "send_alerts",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: CertificateTransparencyMonitorState,
) -> dict[str, Any]:
    """Generate the final CT monitoring report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    report: dict[str, Any] = {
        "watched_domains": state.watched_domains,
        "total_certs_scanned": state.total_certs_scanned,
        "anomalies_found": state.anomalies_found,
        "alerts_sent": state.alerts_sent,
        "impersonation_attempts": state.impersonation_attempts,
        "duration_ms": duration_ms,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "watched_domains": state.watched_domains,
                "total_certs": state.total_certs_scanned,
                "anomalies": state.anomalies[:10],
                "ownership_results": state.ownership_results[:10],
                "alerts_sent": state.alerts_sent,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate CT report:\n{ctx}",
            schema=CTReportOutput,
        )
        if isinstance(llm_out, CTReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "top_risks": llm_out.top_risks,
                    "recommendations": llm_out.recommendations,
                    "risk_rating": llm_out.risk_rating,
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

    # Record metrics
    await toolkit.record_metric(
        request_id=state.request_id,
        outcome={
            "total_certs": state.total_certs_scanned,
            "anomalies_found": state.anomalies_found,
            "impersonation_attempts": state.impersonation_attempts,
            "alerts_sent": state.alerts_sent,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.anomalies_found} anomalies",
        f"Report generated, alerts={state.alerts_sent}",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": CTMStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
