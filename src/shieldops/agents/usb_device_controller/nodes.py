"""USB Device Controller Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import USBStage
from .prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_REPORT,
    USBAnalysisResult,
    USBReportResult,
)
from .tools import USBDeviceControllerToolkit

logger = structlog.get_logger()

_toolkit: USBDeviceControllerToolkit | None = None


async def scan_devices(
    state: dict[str, Any], toolkit: USBDeviceControllerToolkit
) -> dict[str, Any]:
    """Scan for USB devices."""
    logger.info("usb.node.scan")
    tenant_id = state.get("tenant_id", "")
    devices = await toolkit.scan_devices(tenant_id)
    return {
        "stage": USBStage.CHECK_WHITELIST.value,
        "connected_devices": devices,
        "total_devices": len(devices),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Scanned {len(devices)} USB devices"],
    }


async def check_whitelist(
    state: dict[str, Any], toolkit: USBDeviceControllerToolkit
) -> dict[str, Any]:
    """Check devices against whitelist."""
    logger.info("usb.node.whitelist")
    devices = state.get("connected_devices", [])
    unauthorized, whitelisted, unauth_count = await toolkit.check_whitelist(devices)
    return {
        "stage": USBStage.MONITOR_TRANSFERS.value,
        "unauthorized_devices": unauthorized,
        "whitelisted_count": whitelisted,
        "unauthorized_count": unauth_count,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"{whitelisted} whitelisted, {unauth_count} unauthorized"],
    }


async def monitor_transfers(
    state: dict[str, Any], toolkit: USBDeviceControllerToolkit
) -> dict[str, Any]:
    """Monitor USB data transfers."""
    logger.info("usb.node.transfers")
    devices = state.get("connected_devices", [])
    transfers, blocked, suspicious = await toolkit.monitor_transfers(devices)

    reasoning = f"Monitored {len(transfers)} transfers, {blocked} blocked, {suspicious} suspicious"

    if transfers:
        try:
            ctx = json.dumps(
                {
                    "transfers": transfers[:10],
                    "blocked": blocked,
                    "suspicious": suspicious,
                },
                default=str,
            )
            result = cast(
                USBAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_ANALYZE,
                    user_prompt=f"USB transfer analysis:\n{ctx}",
                    schema=USBAnalysisResult,
                ),
            )
            reasoning = f"{result.summary}. {reasoning}"
        except Exception:
            logger.debug("llm_fallback", agent="usb", node="transfers")

    return {
        "stage": USBStage.ENFORCE_POLICY.value,
        "transfers": transfers,
        "blocked_transfers": blocked,
        "suspicious_transfers": suspicious,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def enforce_policy(
    state: dict[str, Any], toolkit: USBDeviceControllerToolkit
) -> dict[str, Any]:
    """Enforce USB policies."""
    logger.info("usb.node.enforce")
    unauthorized = state.get("unauthorized_devices", [])
    transfers = state.get("transfers", [])
    enforcements, count = await toolkit.enforce_policy(unauthorized, transfers)
    return {
        "stage": USBStage.REPORT.value,
        "enforcements": enforcements,
        "policies_applied": count,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Applied {count} policy enforcements"],
    }


async def generate_report(
    state: dict[str, Any], toolkit: USBDeviceControllerToolkit
) -> dict[str, Any]:
    """Generate USB device control report."""
    logger.info("usb.node.report")
    total = state.get("total_devices", 0)
    unauth = state.get("unauthorized_count", 0)
    blocked = state.get("blocked_transfers", 0)
    risk = min(unauth * 20.0 + blocked * 15.0, 100.0)

    summary = (
        f"USB control: {total} devices, {unauth} unauthorized, "
        f"{blocked} transfers blocked, risk={risk:.1f}"
    )

    try:
        ctx = json.dumps(
            {
                "total_devices": total,
                "unauthorized": unauth,
                "blocked_transfers": blocked,
                "suspicious": state.get("suspicious_transfers", 0),
                "enforcements": state.get("policies_applied", 0),
            },
            default=str,
        )
        result = cast(
            USBReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"USB report:\n{ctx}",
                schema=USBReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("llm_fallback", agent="usb", node="report")

    return {
        "stage": USBStage.REPORT.value,
        "risk_score": risk,
        "summary": summary,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
