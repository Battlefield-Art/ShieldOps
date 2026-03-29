"""Mobile Device Manager Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import MDMStage
from .prompts import (
    SYSTEM_COMPLIANCE,
    SYSTEM_REPORT,
    ComplianceAnalysisResult,
    MDMReportResult,
)
from .tools import MobileDeviceManagerToolkit

logger = structlog.get_logger()

_toolkit: MobileDeviceManagerToolkit | None = None


def set_toolkit(tk: MobileDeviceManagerToolkit) -> None:
    global _toolkit
    _toolkit = tk


async def discover_devices(
    state: dict[str, Any], toolkit: MobileDeviceManagerToolkit
) -> dict[str, Any]:
    """Discover mobile devices in the tenant."""
    logger.info("mdm.node.discover")
    tenant_id = state.get("tenant_id", "")
    devices = await toolkit.discover_devices(tenant_id)
    return {
        "stage": MDMStage.CHECK_ENROLLMENT.value,
        "devices": devices,
        "total_devices": len(devices),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(devices)} mobile devices"],
    }


async def check_enrollment(
    state: dict[str, Any], toolkit: MobileDeviceManagerToolkit
) -> dict[str, Any]:
    """Check device enrollment status."""
    logger.info("mdm.node.enrollment")
    devices = state.get("devices", [])
    unenrolled_count, _ = await toolkit.check_enrollment(devices)
    return {
        "stage": MDMStage.ASSESS_COMPLIANCE.value,
        "unenrolled_count": unenrolled_count,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"{unenrolled_count} devices not enrolled"],
    }


async def assess_compliance(
    state: dict[str, Any], toolkit: MobileDeviceManagerToolkit
) -> dict[str, Any]:
    """Assess device compliance."""
    logger.info("mdm.node.compliance")
    devices = state.get("devices", [])
    violations, compliant, non_compliant = await toolkit.assess_compliance(devices)

    reasoning = f"Compliance: {compliant} compliant, {non_compliant} non-compliant"

    if violations:
        try:
            ctx = json.dumps(
                {
                    "devices": len(devices),
                    "violations": violations[:10],
                    "compliant": compliant,
                    "non_compliant": non_compliant,
                },
                default=str,
            )
            result = cast(
                ComplianceAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_COMPLIANCE,
                    user_prompt=f"Device compliance:\n{ctx}",
                    schema=ComplianceAnalysisResult,
                ),
            )
            reasoning = f"{result.summary}. {reasoning}"
        except Exception:
            logger.debug("llm_fallback", agent="mdm", node="compliance")

    return {
        "stage": MDMStage.CHECK_APPS.value,
        "violations": violations,
        "compliant_count": compliant,
        "non_compliant_count": non_compliant,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def check_apps(state: dict[str, Any], toolkit: MobileDeviceManagerToolkit) -> dict[str, Any]:
    """Check for blocked apps."""
    logger.info("mdm.node.apps")
    devices = state.get("devices", [])
    blocked = await toolkit.check_apps(devices)
    return {
        "stage": MDMStage.ENFORCE_POLICIES.value,
        "blocked_apps": blocked,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Found {len(blocked)} blocked apps"],
    }


async def enforce_policies(
    state: dict[str, Any], toolkit: MobileDeviceManagerToolkit
) -> dict[str, Any]:
    """Enforce MDM policies."""
    logger.info("mdm.node.enforce")
    violations = state.get("violations", [])
    blocked_apps = state.get("blocked_apps", [])
    actions, enc_enforced = await toolkit.enforce_policies(violations, blocked_apps)
    return {
        "stage": MDMStage.REPORT.value,
        "actions_taken": actions,
        "encryption_enforced": enc_enforced,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Enforced {len(actions)} policy actions"],
    }


async def generate_report(
    state: dict[str, Any], toolkit: MobileDeviceManagerToolkit
) -> dict[str, Any]:
    """Generate MDM report."""
    logger.info("mdm.node.report")
    total = state.get("total_devices", 0)
    compliant = state.get("compliant_count", 0)
    rate = (compliant / total * 100) if total else 0.0

    summary = (
        f"MDM fleet: {total} devices, {compliant} compliant "
        f"({rate:.1f}%), {state.get('unenrolled_count', 0)} unenrolled"
    )

    try:
        ctx = json.dumps(
            {
                "total_devices": total,
                "compliant": compliant,
                "non_compliant": state.get("non_compliant_count", 0),
                "unenrolled": state.get("unenrolled_count", 0),
                "blocked_apps": len(state.get("blocked_apps", [])),
                "actions": len(state.get("actions_taken", [])),
            },
            default=str,
        )
        result = cast(
            MDMReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"MDM report:\n{ctx}",
                schema=MDMReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("llm_fallback", agent="mdm", node="report")

    return {
        "stage": MDMStage.REPORT.value,
        "summary": summary,
        "compliance_rate": round(rate, 1),
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
