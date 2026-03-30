"""Certificate Lifecycle Manager Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    Certificate,
    CertStatus,
    CLMStage,
)
from .prompts import (
    SYSTEM_COMPLIANCE,
    SYSTEM_EXPIRY_ANALYSIS,
    SYSTEM_REPORT,
    CLMReportResult,
    ComplianceAnalysisResult,
    ExpiryAnalysisResult,
)
from .tools import CertificateLifecycleManagerToolkit

logger = structlog.get_logger()


async def discover_certs(
    state: dict[str, Any],
    toolkit: CertificateLifecycleManagerToolkit,
) -> dict[str, Any]:
    """Discover TLS/SSL certificates across infrastructure."""
    logger.info("cert_lifecycle.node.discover")

    tenant_id = state.get("tenant_id", "")
    certs = await toolkit.discover_certificates(tenant_id)
    certs_data = [c.model_dump(mode="json") for c in certs]

    return {
        "stage": CLMStage.CHECK_EXPIRY.value,
        "certificates": certs_data,
        "total_certs": len(certs),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(certs)} certificates"],
    }


async def check_expiry(
    state: dict[str, Any],
    toolkit: CertificateLifecycleManagerToolkit,
) -> dict[str, Any]:
    """Check certificate expiry status."""
    logger.info("cert_lifecycle.node.check_expiry")

    raw_certs = state.get("certificates", [])
    certs = [Certificate(**c) for c in raw_certs]
    checks = await toolkit.check_expiry(certs)
    checks_data = [c.model_dump(mode="json") for c in checks]

    expiring = sum(1 for c in checks if c.status == CertStatus.EXPIRING_SOON)
    expired = sum(1 for c in checks if c.status == CertStatus.EXPIRED)
    reasoning = f"Expiry check: {expiring} expiring soon, {expired} expired"

    if checks:
        try:
            context = json.dumps(
                {
                    "total_certs": len(checks),
                    "expiring": expiring,
                    "expired": expired,
                    "checks": [
                        {
                            "cn": c.common_name,
                            "status": c.status,
                            "days_remaining": c.days_remaining,
                            "urgency": c.urgency,
                        }
                        for c in checks[:15]
                    ],
                },
                default=str,
            )
            result = cast(
                ExpiryAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_EXPIRY_ANALYSIS,
                    user_prompt=(f"Expiry analysis:\n{context}"),
                    schema=ExpiryAnalysisResult,
                ),
            )
            reasoning = f"{result.summary}. {reasoning}"
        except Exception:
            logger.debug(
                "llm_fallback",
                agent="cert_lifecycle",
                node="check_expiry",
            )

    return {
        "stage": CLMStage.VALIDATE_CONFIG.value,
        "expiry_checks": checks_data,
        "expiring_count": expiring,
        "expired_count": expired,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def validate_config(
    state: dict[str, Any],
    toolkit: CertificateLifecycleManagerToolkit,
) -> dict[str, Any]:
    """Validate certificate configurations."""
    logger.info("cert_lifecycle.node.validate_config")

    raw_certs = state.get("certificates", [])
    certs = [Certificate(**c) for c in raw_certs]
    validations = await toolkit.validate_config(certs)
    validations_data = [v.model_dump(mode="json") for v in validations]

    non_compliant = sum(1 for v in validations if not v.compliant)
    reasoning = f"Config validation: {non_compliant} non-compliant certificates"

    if validations:
        try:
            context = json.dumps(
                {
                    "total": len(validations),
                    "non_compliant": non_compliant,
                    "issues": [
                        {
                            "cn": v.common_name,
                            "compliant": v.compliant,
                            "issues": v.issues,
                        }
                        for v in validations
                        if not v.compliant
                    ],
                },
                default=str,
            )
            result = cast(
                ComplianceAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_COMPLIANCE,
                    user_prompt=(f"Compliance context:\n{context}"),
                    schema=ComplianceAnalysisResult,
                ),
            )
            reasoning = f"{result.summary}. {reasoning}"
        except Exception:
            logger.debug(
                "llm_fallback",
                agent="cert_lifecycle",
                node="validate_config",
            )

    return {
        "stage": CLMStage.PLAN_RENEWAL.value,
        "config_validations": validations_data,
        "non_compliant_count": non_compliant,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def plan_renewal(
    state: dict[str, Any],
    toolkit: CertificateLifecycleManagerToolkit,
) -> dict[str, Any]:
    """Plan certificate renewals."""
    logger.info("cert_lifecycle.node.plan_renewal")

    raw_certs = state.get("certificates", [])
    certs = [Certificate(**c) for c in raw_certs]

    from .models import ConfigValidation, ExpiryCheck

    raw_checks = state.get("expiry_checks", [])
    raw_validations = state.get("config_validations", [])
    checks = [ExpiryCheck(**e) for e in raw_checks]
    validations = [ConfigValidation(**v) for v in raw_validations]

    plans = await toolkit.plan_renewals(certs, checks, validations)
    plans_data = [p.model_dump(mode="json") for p in plans]

    return {
        "stage": CLMStage.EXECUTE_RENEWAL.value,
        "renewal_plans": plans_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Planned {len(plans)} certificate renewals"],
    }


async def execute_renewal(
    state: dict[str, Any],
    toolkit: CertificateLifecycleManagerToolkit,
) -> dict[str, Any]:
    """Execute certificate renewals."""
    logger.info("cert_lifecycle.node.execute_renewal")

    from .models import RenewalPlan

    raw_plans = state.get("renewal_plans", [])
    plans = [RenewalPlan(**p) for p in raw_plans]
    executions = await toolkit.execute_renewals(plans)
    exec_data = [e.model_dump(mode="json") for e in executions]

    renewed = sum(1 for e in executions if e.success)

    return {
        "stage": CLMStage.REPORT.value,
        "renewal_executions": exec_data,
        "renewed_count": renewed,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Executed {len(executions)} renewals, {renewed} successful"],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: CertificateLifecycleManagerToolkit,
) -> dict[str, Any]:
    """Generate certificate lifecycle management report."""
    logger.info("cert_lifecycle.node.report")

    total = state.get("total_certs", 0)
    expiring = state.get("expiring_count", 0)
    expired = state.get("expired_count", 0)
    renewed = state.get("renewed_count", 0)
    non_compliant = state.get("non_compliant_count", 0)

    summary = (
        f"Managed {total} certificates: "
        f"{expiring} expiring, {expired} expired, "
        f"{renewed} renewed, "
        f"{non_compliant} non-compliant"
    )

    try:
        context = json.dumps(
            {
                "total_certs": total,
                "expiring_count": expiring,
                "expired_count": expired,
                "renewed_count": renewed,
                "non_compliant_count": non_compliant,
                "renewal_executions": state.get("renewal_executions", [])[:10],
            },
            default=str,
        )
        result = cast(
            CLMReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Certificate report context:\n{context}"),
                schema=CLMReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cert_lifecycle",
            node="report",
        )

    return {
        "stage": CLMStage.REPORT.value,
        "summary": summary,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
