"""Certificate Manager Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import Certificate, CertStage, ExpiryAlert, RotationPlan
from .prompts import (
    SYSTEM_EXPIRY_ANALYSIS,
    SYSTEM_REPORT,
    SYSTEM_ROTATION_PLAN,
    CertReportResult,
    ExpiryAnalysisResult,
    RotationPlanResult,
)
from .tools import CertificateManagerToolkit

logger = structlog.get_logger()


async def discover_certs(
    state: dict[str, Any], toolkit: CertificateManagerToolkit
) -> dict[str, Any]:
    """Discover all certificates across infrastructure."""
    logger.info("cert_manager.node.discover_certs")

    tenant_id = state.get("tenant_id", "")
    certs = await toolkit.discover_certificates(tenant_id)
    certs_data = [c.model_dump(mode="json") for c in certs]

    return {
        "stage": CertStage.CHECK_EXPIRY.value,
        "certificates": certs_data,
        "total_certs": len(certs),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(certs)} certificates"],
    }


async def check_expiry(state: dict[str, Any], toolkit: CertificateManagerToolkit) -> dict[str, Any]:
    """Check certificates for upcoming expiry."""
    logger.info("cert_manager.node.check_expiry")

    raw_certs = state.get("certificates", [])
    certs = [Certificate(**c) for c in raw_certs]
    alerts = await toolkit.check_expiry(certs)
    alerts_data = [a.model_dump() for a in alerts]

    reasoning_note = f"Found {len(alerts)} expiry alerts"

    if alerts:
        try:
            context = json.dumps(
                {
                    "total_certs": len(certs),
                    "alerts": [
                        {
                            "domain": a.domain,
                            "days_remaining": a.days_remaining,
                            "severity": a.severity,
                        }
                        for a in alerts
                    ],
                },
                default=str,
            )
            result = cast(
                ExpiryAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_EXPIRY_ANALYSIS,
                    user_prompt=f"Expiry analysis context:\n{context}",
                    schema=ExpiryAnalysisResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug("llm_fallback", agent="cert_manager", node="check_expiry")

    return {
        "stage": CertStage.VALIDATE_CHAINS.value,
        "expiry_alerts": alerts_data,
        "expiring_count": len(alerts),
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def validate_chains(
    state: dict[str, Any], toolkit: CertificateManagerToolkit
) -> dict[str, Any]:
    """Validate certificate chains."""
    logger.info("cert_manager.node.validate_chains")

    raw_certs = state.get("certificates", [])
    certs = [Certificate(**c) for c in raw_certs]
    validations = await toolkit.validate_chains(certs)
    validations_data = [v.model_dump() for v in validations]

    invalid_count = sum(1 for v in validations if not v.chain_valid)
    return {
        "stage": CertStage.PLAN_ROTATION.value,
        "chain_validations": validations_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Validated {len(validations)} chains, {invalid_count} have issues"],
    }


async def plan_rotation(
    state: dict[str, Any], toolkit: CertificateManagerToolkit
) -> dict[str, Any]:
    """Plan certificate rotations."""
    logger.info("cert_manager.node.plan_rotation")

    raw_alerts = state.get("expiry_alerts", [])
    raw_certs = state.get("certificates", [])
    alerts = [ExpiryAlert(**a) for a in raw_alerts]
    certs = [Certificate(**c) for c in raw_certs]

    plans = await toolkit.plan_rotations(alerts, certs)
    plans_data = [p.model_dump() for p in plans]

    reasoning_note = f"Created {len(plans)} rotation plans"

    if plans:
        try:
            context = json.dumps(
                {
                    "plans": [
                        {"domain": p.domain, "action": p.action, "provider": p.provider}
                        for p in plans
                    ],
                },
                default=str,
            )
            result = cast(
                RotationPlanResult,
                await llm_structured(
                    system_prompt=SYSTEM_ROTATION_PLAN,
                    user_prompt=f"Rotation plan context:\n{context}",
                    schema=RotationPlanResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug("llm_fallback", agent="cert_manager", node="plan_rotation")

    return {
        "stage": CertStage.EXECUTE_ROTATION.value,
        "rotation_plans": plans_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def execute_rotation(
    state: dict[str, Any], toolkit: CertificateManagerToolkit
) -> dict[str, Any]:
    """Execute certificate rotations."""
    logger.info("cert_manager.node.execute_rotation")

    raw_plans = state.get("rotation_plans", [])
    executed: list[dict[str, Any]] = []
    rotated = 0

    for raw in raw_plans:
        plan = RotationPlan(**raw)
        result = await toolkit.execute_rotation(plan)
        executed.append(result.model_dump())
        if result.status == "completed":
            rotated += 1

    return {
        "stage": CertStage.REPORT.value,
        "rotation_plans": executed,
        "rotated_count": rotated,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Executed {len(executed)} rotations, {rotated} completed"],
    }


async def generate_report(
    state: dict[str, Any], toolkit: CertificateManagerToolkit
) -> dict[str, Any]:
    """Generate certificate management report."""
    logger.info("cert_manager.node.report")

    total = state.get("total_certs", 0)
    expiring = state.get("expiring_count", 0)
    rotated = state.get("rotated_count", 0)
    summary = f"Managed {total} certificates: {expiring} expiring, {rotated} rotated"

    try:
        context = json.dumps(
            {
                "total_certs": total,
                "expiring_count": expiring,
                "rotated_count": rotated,
                "certificates": state.get("certificates", [])[:10],
                "chain_validations": state.get("chain_validations", [])[:10],
            },
            default=str,
        )
        result = cast(
            CertReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Report context:\n{context}",
                schema=CertReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("llm_fallback", agent="cert_manager", node="report")

    return {
        "stage": CertStage.REPORT.value,
        "summary": summary,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
