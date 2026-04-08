"""Node implementations for the Mobile Threat Defender."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.mobile_threat_defender.models import (
    MobileThreatDefenderState,
    MTDStage,
    ReasoningStep,
)
from shieldops.agents.mobile_threat_defender.prompts import (
    SYSTEM_ANALYZE_APPS,
    SYSTEM_CHECK_NETWORK,
    SYSTEM_DETECT_THREATS,
    SYSTEM_ENFORCE_POLICY,
    SYSTEM_SCAN_DEVICE,
    AppAnalysisOutput,
    DeviceScanOutput,
    NetworkCheckOutput,
    PolicyEnforcementOutput,
    ThreatDetectionOutput,
)
from shieldops.agents.mobile_threat_defender.tools import (
    MobileThreatDefenderToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: MobileThreatDefenderToolkit | None = None


def _get_toolkit() -> MobileThreatDefenderToolkit:
    if _toolkit is None:
        return MobileThreatDefenderToolkit()
    return _toolkit


def _step(
    state: MobileThreatDefenderState,
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


async def scan_device(
    state: MobileThreatDefenderState,
) -> dict[str, Any]:
    """Scan mobile devices for posture assessment."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scans = await toolkit.scan_device(state.defend_config)
    compromised = sum(1 for s in scans if s.get("is_rooted") or s.get("is_jailbroken"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "device_count": len(scans),
                "compromised": compromised,
                "scans": scans[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SCAN_DEVICE,
            user_prompt=(f"Device scan context:\n{ctx}"),
            schema=DeviceScanOutput,
        )
        if hasattr(llm_result, "compromised_count") and llm_result.compromised_count > compromised:
            compromised = llm_result.compromised_count
        logger.info(
            "llm_enhanced",
            node="scan_device",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_device",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "scan_device",
        f"scanning {len(scans)} devices",
        f"{compromised} compromised devices found",
        elapsed,
        "mdm_client",
    )
    await toolkit.record_metric(
        "devices_scanned",
        float(len(scans)),
    )

    return {
        "device_scans": scans,
        "compromised_device_count": compromised,
        "stage": MTDStage.ANALYZE_APPS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "scan_device",
        "session_start": start,
    }


async def analyze_apps(
    state: MobileThreatDefenderState,
) -> dict[str, Any]:
    """Analyze applications on scanned devices."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_apps(
        state.device_scans,
    )
    malicious = sum(1 for a in analyses if a.get("is_malicious"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "device_count": len(state.device_scans),
                "app_count": len(analyses),
                "malicious": malicious,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE_APPS,
            user_prompt=(f"App analysis context:\n{ctx}"),
            schema=AppAnalysisOutput,
        )
        if hasattr(llm_result, "malicious_apps") and llm_result.malicious_apps > malicious:
            malicious = llm_result.malicious_apps
        logger.info(
            "llm_enhanced",
            node="analyze_apps",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_apps",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "analyze_apps",
        f"analyzing apps on {len(state.device_scans)} devices",
        f"{len(analyses)} apps, {malicious} malicious",
        elapsed,
        "app_reputation",
    )

    return {
        "app_analyses": analyses,
        "malicious_app_count": malicious,
        "stage": MTDStage.CHECK_NETWORK,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_apps",
    }


async def check_network(
    state: MobileThreatDefenderState,
) -> dict[str, Any]:
    """Check network security for devices."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    checks = await toolkit.check_network(
        state.device_scans,
    )
    net_threats = sum(
        1
        for c in checks
        if c.get("mitm_detected") or c.get("rogue_ap_detected") or c.get("dns_poisoning")
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "device_count": len(state.device_scans),
                "checks": checks[:10],
                "threats": net_threats,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CHECK_NETWORK,
            user_prompt=(f"Network check context:\n{ctx}"),
            schema=NetworkCheckOutput,
        )
        if hasattr(llm_result, "threats_detected") and llm_result.threats_detected > net_threats:
            net_threats = llm_result.threats_detected
        logger.info(
            "llm_enhanced",
            node="check_network",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="check_network",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "check_network",
        f"checking {len(state.device_scans)} devices",
        f"{net_threats} network threats detected",
        elapsed,
        "network_monitor",
    )

    return {
        "network_checks": checks,
        "network_threat_count": net_threats,
        "stage": MTDStage.DETECT_THREATS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "check_network",
    }


async def detect_threats(
    state: MobileThreatDefenderState,
) -> dict[str, Any]:
    """Detect threats from combined analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    threats = await toolkit.detect_threats(
        state.device_scans,
        state.app_analyses,
        state.network_checks,
    )
    severity_order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }
    max_sev = max(
        (t.get("severity", "low") for t in threats),
        key=lambda s: severity_order.get(s, 0),
        default="low",
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scan_count": len(state.device_scans),
                "app_count": len(state.app_analyses),
                "network_count": len(state.network_checks),
                "threats": threats[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DETECT_THREATS,
            user_prompt=(f"Threat detection context:\n{ctx}"),
            schema=ThreatDetectionOutput,
        )
        if hasattr(llm_result, "threats"):
            logger.info(
                "llm_enhanced",
                node="detect_threats",
                llm_threats=len(llm_result.threats),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_threats",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "detect_threats",
        "combining scan, app, and network findings",
        f"found {len(threats)} threats, max={max_sev}",
        elapsed,
        "threat_intel",
    )
    await toolkit.record_metric(
        "threats",
        float(len(threats)),
    )

    return {
        "detected_threats": threats,
        "max_threat_severity": max_sev,
        "stage": MTDStage.ENFORCE_POLICY,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "detect_threats",
    }


async def enforce_policy(
    state: MobileThreatDefenderState,
) -> dict[str, Any]:
    """Enforce security policies based on threats."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.enforce_policy(
        state.detected_threats,
        state.device_scans,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "threat_count": len(state.detected_threats),
                "device_count": len(state.device_scans),
                "actions": actions[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ENFORCE_POLICY,
            user_prompt=(f"Enforcement context:\n{ctx}"),
            schema=PolicyEnforcementOutput,
        )
        if hasattr(llm_result, "actions_taken"):
            logger.info(
                "llm_enhanced",
                node="enforce_policy",
                llm_actions=llm_result.actions_taken,
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enforce_policy",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "enforce_policy",
        f"enforcing on {len(state.detected_threats)} threats",
        f"took {len(actions)} actions",
        elapsed,
        "policy_engine",
    )

    return {
        "policy_actions": actions,
        "stage": MTDStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "enforce_policy",
    }


async def generate_report(
    state: MobileThreatDefenderState,
) -> dict[str, Any]:
    """Generate final mobile threat defense report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "devices_scanned": len(state.device_scans),
        "compromised_devices": state.compromised_device_count,
        "apps_analyzed": len(state.app_analyses),
        "malicious_apps": state.malicious_app_count,
        "network_threats": state.network_threat_count,
        "total_threats": len(state.detected_threats),
        "max_severity": state.max_threat_severity,
        "policy_actions": len(state.policy_actions),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )
    await toolkit.record_metric(
        "devices_scanned",
        float(len(state.device_scans)),
    )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "generate_report",
        f"finalizing defense {state.request_id}",
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
