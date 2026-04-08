"""Cloud Audit Logger Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AuditEvent,
    AuditStage,
    SuspiciousActivity,
)
from .tools import CloudAuditLoggerToolkit

logger = structlog.get_logger()

_toolkit: CloudAuditLoggerToolkit | None = None


def _get_toolkit() -> CloudAuditLoggerToolkit:
    global _toolkit
    if _toolkit is None:
        _toolkit = CloudAuditLoggerToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def ingest_logs(state: dict[str, Any], toolkit: CloudAuditLoggerToolkit) -> dict[str, Any]:
    """Ingest audit logs from cloud providers."""
    logger.info("audit_logger.node.ingest_logs")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    sources = state.get("sources", ["cloudtrail"])
    time_range = state.get("time_range_hours", 24)

    events = await toolkit.ingest_audit_logs(tenant_id, sources, time_range)
    events_data = [e.model_dump() for e in events]

    return {
        "stage": AuditStage.PARSE_EVENTS.value,
        "audit_events": events_data,
        "current_step": "ingest_logs",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Ingested {len(events)} events from {', '.join(sources)}"],
    }


async def detect_anomalies(
    state: dict[str, Any], toolkit: CloudAuditLoggerToolkit
) -> dict[str, Any]:
    """Detect suspicious activities from audit events."""
    logger.info("audit_logger.node.detect_anomalies")
    state = _to_dict(state)

    raw_events = state.get("audit_events", [])
    events = [AuditEvent(**e) for e in raw_events]

    activities = await toolkit.detect_suspicious_activity(events)
    activities_data = [a.model_dump() for a in activities]

    critical = sum(1 for a in activities if a.severity == "critical")
    high = sum(1 for a in activities if a.severity == "high")

    reasoning_note = (
        f"Detected {len(activities)} suspicious activities: {critical} critical, {high} high"
    )

    try:
        from .prompts import SYSTEM_ANOMALY_DETECTION, AnomalyAnalysisOutput

        context = json.dumps(
            {
                "total": len(activities),
                "critical": critical,
                "high": high,
                "types": list({a.activity_type for a in activities}),
                "principals": list({a.principal for a in activities}),
            },
            default=str,
        )
        llm_result = cast(
            AnomalyAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_ANOMALY_DETECTION,
                user_prompt=f"Audit anomaly context:\n{context}",
                schema=AnomalyAnalysisOutput,
            ),
        )
        logger.info("llm_enhanced", agent="audit_logger", node="detect")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="audit_logger", node="detect")

    return {
        "stage": AuditStage.CORRELATE_ACTIVITY.value,
        "suspicious_activities": activities_data,
        "current_step": "detect_anomalies",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def correlate_activity(
    state: dict[str, Any], toolkit: CloudAuditLoggerToolkit
) -> dict[str, Any]:
    """Correlate suspicious activities into attack chains."""
    logger.info("audit_logger.node.correlate_activity")
    state = _to_dict(state)

    raw_activities = state.get("suspicious_activities", [])
    activities = [SuspiciousActivity(**a) for a in raw_activities]

    correlations = await toolkit.correlate_activities(activities)
    correlations_data = [c.model_dump() for c in correlations]

    reasoning_note = f"Correlated into {len(correlations)} attack chains"

    try:
        from .prompts import SYSTEM_CORRELATION, CorrelationOutput

        context = json.dumps(
            {
                "chains": len(correlations),
                "activities": len(activities),
                "chain_types": [c.chain_type for c in correlations],
            },
            default=str,
        )
        llm_result = cast(
            CorrelationOutput,
            await llm_structured(
                system_prompt=SYSTEM_CORRELATION,
                user_prompt=f"Correlation context:\n{context}",
                schema=CorrelationOutput,
            ),
        )
        logger.info("llm_enhanced", agent="audit_logger", node="correlate")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="audit_logger", node="correlate")

    return {
        "stage": AuditStage.ASSESS_RISK.value,
        "correlations": correlations_data,
        "current_step": "correlate_activity",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def assess_risk(state: dict[str, Any], toolkit: CloudAuditLoggerToolkit) -> dict[str, Any]:
    """Assess overall risk from audit findings."""
    logger.info("audit_logger.node.assess_risk")
    state = _to_dict(state)

    raw_activities = state.get("suspicious_activities", [])
    raw_correlations = state.get("correlations", [])
    raw_events = state.get("audit_events", [])

    risk_scores = [a.get("risk_score", 0.0) for a in raw_activities]
    risk_score = round(max(risk_scores) if risk_scores else 0.0, 1)

    elapsed = round(
        (time.time() - state.get("session_start", time.time())) * 1000,
        1,
    )

    stats = {
        "events_ingested": len(raw_events),
        "suspicious_activities": len(raw_activities),
        "attack_chains": len(raw_correlations),
        "risk_score": risk_score,
        "sources": state.get("sources", []),
    }

    report_summary = (
        f"Risk score: {risk_score}/100."
        f" {len(raw_events)} events,"
        f" {len(raw_activities)} suspicious,"
        f" {len(raw_correlations)} chains."
    )

    try:
        from .prompts import (
            SYSTEM_RISK_ASSESSMENT,
            RiskAssessmentOutput,
        )

        context = json.dumps(stats, default=str)
        llm_result = cast(
            RiskAssessmentOutput,
            await llm_structured(
                system_prompt=SYSTEM_RISK_ASSESSMENT,
                user_prompt=f"Risk context:\n{context}",
                schema=RiskAssessmentOutput,
            ),
        )
        logger.info("llm_enhanced", agent="audit_logger", node="risk")
        report_summary = llm_result.summary
    except Exception:
        logger.debug("llm_fallback", agent="audit_logger", node="risk")

    return {
        "stage": AuditStage.REPORT.value,
        "risk_score": risk_score,
        "stats": stats,
        "session_duration_ms": elapsed,
        "current_step": "assess_risk",
        "reasoning_chain": state.get("reasoning_chain", []) + [report_summary],
    }
