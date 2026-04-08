"""Patch Compliance Checker Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import PatchStage
from .prompts import (
    SYSTEM_REPORT,
    SYSTEM_RISK,
    PatchReportResult,
    PatchRiskResult,
)
from .tools import PatchComplianceCheckerToolkit

logger = structlog.get_logger()

_toolkit: PatchComplianceCheckerToolkit | None = None


async def inventory_systems(
    state: dict[str, Any], toolkit: PatchComplianceCheckerToolkit
) -> dict[str, Any]:
    """Inventory fleet systems."""
    logger.info("patch.node.inventory")
    tenant_id = state.get("tenant_id", "")
    systems = await toolkit.inventory_systems(tenant_id)
    return {
        "stage": PatchStage.SCAN_PATCHES.value,
        "systems": systems,
        "total_systems": len(systems),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Inventoried {len(systems)} systems"],
    }


async def scan_patches(
    state: dict[str, Any], toolkit: PatchComplianceCheckerToolkit
) -> dict[str, Any]:
    """Scan for missing patches."""
    logger.info("patch.node.scan")
    systems = state.get("systems", [])
    missing, total, critical = await toolkit.scan_patches(systems)
    return {
        "stage": PatchStage.ASSESS_RISK.value,
        "missing_patches": missing,
        "total_missing": total,
        "critical_missing": critical,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Found {total} missing patches ({critical} critical)"],
    }


async def assess_risk(
    state: dict[str, Any], toolkit: PatchComplianceCheckerToolkit
) -> dict[str, Any]:
    """Assess risk of unpatched systems."""
    logger.info("patch.node.risk")
    missing = state.get("missing_patches", [])
    systems = state.get("systems", [])
    assessments, fleet_risk = await toolkit.assess_risk(missing, systems)

    reasoning = f"Fleet risk score: {fleet_risk}"

    if assessments:
        try:
            ctx = json.dumps(
                {
                    "assessments": assessments[:10],
                    "fleet_risk": fleet_risk,
                    "systems": len(systems),
                },
                default=str,
            )
            result = cast(
                PatchRiskResult,
                await llm_structured(
                    system_prompt=SYSTEM_RISK,
                    user_prompt=f"Patch risk:\n{ctx}",
                    schema=PatchRiskResult,
                ),
            )
            reasoning = f"{result.summary}. {reasoning}"
        except Exception:
            logger.debug("llm_fallback", agent="patch", node="risk")

    return {
        "stage": PatchStage.CHECK_SLA.value,
        "risk_assessments": assessments,
        "fleet_risk_score": fleet_risk,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def check_sla(
    state: dict[str, Any], toolkit: PatchComplianceCheckerToolkit
) -> dict[str, Any]:
    """Check patching SLA compliance."""
    logger.info("patch.node.sla")
    missing = state.get("missing_patches", [])
    violations, rate = await toolkit.check_sla(missing)
    return {
        "stage": PatchStage.SCHEDULE_ROLLOUT.value,
        "sla_violations": violations,
        "sla_compliant_rate": rate,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"SLA compliance: {rate}%, {len(violations)} violations"],
    }


async def schedule_rollout(
    state: dict[str, Any], toolkit: PatchComplianceCheckerToolkit
) -> dict[str, Any]:
    """Schedule patch rollout."""
    logger.info("patch.node.schedule")
    missing = state.get("missing_patches", [])
    assessments = state.get("risk_assessments", [])
    schedule = await toolkit.schedule_rollout(missing, assessments)
    return {
        "stage": PatchStage.REPORT.value,
        "rollout_schedule": schedule,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Scheduled {len(schedule)} patch rollouts"],
    }


async def generate_report(
    state: dict[str, Any], toolkit: PatchComplianceCheckerToolkit
) -> dict[str, Any]:
    """Generate patch compliance report."""
    logger.info("patch.node.report")
    total_sys = state.get("total_systems", 0)
    total_missing = state.get("total_missing", 0)
    critical = state.get("critical_missing", 0)
    sla_rate = state.get("sla_compliant_rate", 0.0)
    patched = total_sys - len({p.get("system_id") for p in state.get("missing_patches", [])})
    rate = (patched / total_sys * 100) if total_sys else 100.0

    summary = (
        f"Patch compliance: {total_sys} systems, "
        f"{total_missing} missing ({critical} critical), "
        f"compliance={rate:.1f}%, SLA={sla_rate}%"
    )

    try:
        ctx = json.dumps(
            {
                "total_systems": total_sys,
                "missing_patches": total_missing,
                "critical": critical,
                "compliance_rate": rate,
                "sla_rate": sla_rate,
                "rollouts": len(state.get("rollout_schedule", [])),
            },
            default=str,
        )
        result = cast(
            PatchReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Patch report:\n{ctx}",
                schema=PatchReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("llm_fallback", agent="patch", node="report")

    return {
        "stage": PatchStage.REPORT.value,
        "summary": summary,
        "compliance_rate": round(rate, 1),
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
