"""Node implementations for the Cloud Database Protector
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cloud_database_protector.models import (
    CDPStage,
    CloudDatabaseProtectorState,
    ReasoningStep,
)
from shieldops.agents.cloud_database_protector.prompts import (
    SYSTEM_ACCESS_AUDIT,
    SYSTEM_ANOMALY,
    SYSTEM_ENCRYPTION,
    SYSTEM_REPORT,
    AccessAuditOutput,
    AnomalyDetectionOutput,
    DatabaseReportOutput,
    EncryptionAssessmentOutput,
)
from shieldops.agents.cloud_database_protector.tools import (
    CloudDatabaseProtectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CloudDatabaseProtectorToolkit | None = None


def _get_toolkit() -> CloudDatabaseProtectorToolkit:
    if _toolkit is None:
        return CloudDatabaseProtectorToolkit()
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
# Node: discover_databases
# ------------------------------------------------------------------


async def discover_databases(
    state: CloudDatabaseProtectorState,
) -> dict[str, Any]:
    """Discover cloud database instances across providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.discover_databases(
        providers=state.providers,
        scope=state.scope,
    )

    databases: list[dict[str, Any]] = list(results)

    step = _step(
        state.reasoning_chain,
        "discover_databases",
        f"Providers: {len(state.providers)}",
        f"Discovered {len(databases)} databases",
        start,
        "db_discovery",
    )

    return {
        "databases": databases,
        "total_databases": len(databases),
        "stage": CDPStage.DISCOVER_DATABASES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "discover_databases",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: audit_access
# ------------------------------------------------------------------


async def audit_access(
    state: CloudDatabaseProtectorState,
) -> dict[str, Any]:
    """Audit access controls for discovered databases."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    audits = await toolkit.audit_access(
        databases=state.databases,
    )

    audit_list: list[dict[str, Any]] = list(audits)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "database_count": len(state.databases),
                "sample": state.databases[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ACCESS_AUDIT,
            user_prompt=f"Audit database access:\n{ctx}",
            schema=AccessAuditOutput,
        )
        if llm_out.risk_users:  # type: ignore[union-attr]
            _rand = random.randint(1000, 9999)  # noqa: S311
            audit_list.append(
                {
                    "audit_id": f"llm-{_rand}",
                    "risk_users": llm_out.risk_users,  # type: ignore[union-attr]
                    "unused": llm_out.unused_accounts,  # type: ignore[union-attr]
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "recommendations": llm_out.recommendations,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="audit_access",
            risk_users=len(llm_out.risk_users),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="audit_access",
        )

    at_risk = sum(
        1 for a in audit_list if a.get("risk_score", 0) > 5 or a.get("risk") in ("critical", "high")
    )

    step = _step(
        state.reasoning_chain,
        "audit_access",
        f"Auditing {len(state.databases)} databases",
        f"Produced {len(audit_list)} audits, {at_risk} at risk",
        start,
        "access_auditor",
    )

    return {
        "access_audits": audit_list,
        "at_risk_count": at_risk,
        "stage": CDPStage.AUDIT_ACCESS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "audit_access",
    }


# ------------------------------------------------------------------
# Node: check_encryption
# ------------------------------------------------------------------


async def check_encryption(
    state: CloudDatabaseProtectorState,
) -> dict[str, Any]:
    """Check encryption configuration for databases."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    checks = await toolkit.check_encryption(
        databases=state.databases,
    )

    check_list: list[dict[str, Any]] = list(checks)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "database_sample": state.databases[:5],
                "audit_sample": state.access_audits[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ENCRYPTION,
            user_prompt=f"Assess encryption posture:\n{ctx}",
            schema=EncryptionAssessmentOutput,
        )
        if llm_out.compliance_gaps:  # type: ignore[union-attr]
            _rand2 = random.randint(1000, 9999)  # noqa: S311
            check_list.append(
                {
                    "check_id": f"llm-{_rand2}",
                    "unencrypted": llm_out.unencrypted_count,  # type: ignore[union-attr]
                    "weak": llm_out.weak_encryption,  # type: ignore[union-attr]
                    "gaps": llm_out.compliance_gaps,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="check_encryption",
            gaps=len(llm_out.compliance_gaps),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="check_encryption",
        )

    step = _step(
        state.reasoning_chain,
        "check_encryption",
        f"Checking {len(state.databases)} databases",
        f"Produced {len(check_list)} encryption checks",
        start,
        "encryption_checker",
    )

    return {
        "encryption_checks": check_list,
        "stage": CDPStage.CHECK_ENCRYPTION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "check_encryption",
    }


# ------------------------------------------------------------------
# Node: detect_anomalies
# ------------------------------------------------------------------


async def detect_anomalies(
    state: CloudDatabaseProtectorState,
) -> dict[str, Any]:
    """Detect anomalous database access patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    anomalies = await toolkit.detect_anomalies(
        databases=state.databases,
        audits=state.access_audits,
    )

    anomaly_list: list[dict[str, Any]] = list(anomalies)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "databases_sample": state.databases[:3],
                "audits_sample": state.access_audits[:3],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANOMALY,
            user_prompt=f"Detect access anomalies:\n{ctx}",
            schema=AnomalyDetectionOutput,
        )
        if llm_out.anomalies:  # type: ignore[union-attr]
            for idx, anom in enumerate(llm_out.anomalies):  # type: ignore[union-attr]
                anomaly_list.append(
                    {
                        "anomaly_id": f"llm-{idx}",
                        "type": anom.get("type", ""),
                        "severity": anom.get("severity", ""),
                        "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    }
                )
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

    step = _step(
        state.reasoning_chain,
        "detect_anomalies",
        f"Scanning {len(state.databases)} databases",
        f"Detected {len(anomaly_list)} anomalies",
        start,
        "anomaly_detector",
    )

    return {
        "anomalies": anomaly_list,
        "anomaly_count": len(anomaly_list),
        "stage": CDPStage.DETECT_ANOMALIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_anomalies",
    }


# ------------------------------------------------------------------
# Node: enforce_policies
# ------------------------------------------------------------------


async def enforce_policies(
    state: CloudDatabaseProtectorState,
) -> dict[str, Any]:
    """Enforce database security policies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    enforcements = await toolkit.enforce_policies(
        anomalies=state.anomalies,
        enforce_mode=state.enforce_mode,
    )

    step = _step(
        state.reasoning_chain,
        "enforce_policies",
        f"Enforcing on {len(state.anomalies)} anomalies",
        f"Applied {len(enforcements)} enforcements",
        start,
        "policy_enforcer",
    )

    return {
        "enforcements": enforcements,
        "enforced_count": len(enforcements),
        "stage": CDPStage.ENFORCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enforce_policies",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: CloudDatabaseProtectorState,
) -> dict[str, Any]:
    """Generate the database protection report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "total_databases": state.total_databases,
        "at_risk_count": state.at_risk_count,
        "anomaly_count": state.anomaly_count,
        "enforced_count": state.enforced_count,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "total_databases": state.total_databases,
                "at_risk": state.at_risk_count,
                "anomalies": state.anomaly_count,
                "enforced": state.enforced_count,
                "audits_sample": state.access_audits[:5],
                "encryption_sample": state.encryption_checks[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate database report:\n{ctx}",
            schema=DatabaseReportOutput,
        )
        if isinstance(llm_out, DatabaseReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "top_risks": llm_out.top_risks,
                    "recommendations": llm_out.recommendations,
                    "compliance_status": llm_out.compliance_status,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                risks=len(llm_out.top_risks),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    await toolkit.record_metric(
        request_id=state.request_id,
        outcome={
            "total_databases": state.total_databases,
            "at_risk": state.at_risk_count,
            "anomalies": state.anomaly_count,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_databases} databases",
        f"Report generated, {state.at_risk_count} at risk",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": CDPStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
