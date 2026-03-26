"""IoT/OT Security Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    DeviceAnomaly,
    IoTDevice,
    ThreatLevel,
)
from .tools import IoTOTSecurityToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_devices(
    state: dict[str, Any],
    toolkit: IoTOTSecurityToolkit,
) -> dict[str, Any]:
    """Discover IoT/OT devices via passive network analysis."""
    logger.info("iot_ot_security.node.discover_devices")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    zones = state.get(
        "network_zones",
        ["iot", "ot", "edge"],
    )
    session_start = time.time()

    devices = await toolkit.discover_devices(
        tenant_id=tenant_id,
        network_zones=zones,
    )
    device_dicts = [d.model_dump() for d in devices]

    unmanaged = [d for d in devices if not d.is_managed]
    ai_connected = [d for d in devices if d.is_ai_connected]
    unmanaged_dicts = [d.model_dump() for d in unmanaged]

    reasoning = (
        f"Discovered {len(devices)} devices across "
        f"{len(zones)} zones: {len(unmanaged)} unmanaged"
        f", {len(ai_connected)} AI-connected"
    )

    # LLM-enhanced device classification
    try:
        from .prompts import (
            SYSTEM_DEVICE_DISCOVERY,
            DeviceDiscoveryResult,
        )

        ctx = json.dumps(
            {
                "tenant_id": tenant_id,
                "zones": zones,
                "total_devices": len(devices),
                "unmanaged_count": len(unmanaged),
                "ai_connected_count": len(ai_connected),
                "devices_summary": device_dicts[:15],
            },
            default=str,
        )
        llm_result = cast(
            DeviceDiscoveryResult,
            await llm_structured(
                system_prompt=SYSTEM_DEVICE_DISCOVERY,
                user_prompt=(f"IoT/OT device discovery:\n{ctx}"),
                schema=DeviceDiscoveryResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="iot_ot_security",
            node="discover_devices",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="iot_ot_security",
            node="discover_devices",
        )

    return {
        "devices_discovered": device_dicts,
        "unmanaged_devices": unmanaged_dicts,
        "session_start": session_start,
        "stage": "discover_devices",
        "current_step": "discover_devices",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def profile_behavior(
    state: dict[str, Any],
    toolkit: IoTOTSecurityToolkit,
) -> dict[str, Any]:
    """Build behavioral baselines for discovered devices."""
    logger.info("iot_ot_security.node.profile_behavior")
    state = _to_dict(state)
    device_dicts = state.get("devices_discovered", [])

    devices = [IoTDevice(**d) for d in device_dicts]
    profiles = await toolkit.profile_behavior(devices)
    profile_dicts = [p.model_dump() for p in profiles]

    ai_profiles = sum(1 for p in profiles if p.ai_data_flow_pattern)
    reasoning = f"Profiled {len(profiles)} devices: {ai_profiles} with AI data flow patterns"

    return {
        "profiles_built": profile_dicts,
        "stage": "profile_behavior",
        "current_step": "profile_behavior",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def detect_anomalies(
    state: dict[str, Any],
    toolkit: IoTOTSecurityToolkit,
) -> dict[str, Any]:
    """Detect behavioral anomalies against baselines."""
    logger.info("iot_ot_security.node.detect_anomalies")
    state = _to_dict(state)
    device_dicts = state.get("devices_discovered", [])
    profile_dicts = state.get("profiles_built", [])

    from .models import BehaviorProfile

    devices = [IoTDevice(**d) for d in device_dicts]
    profiles = [BehaviorProfile(**p) for p in profile_dicts]

    anomalies = await toolkit.detect_anomalies(
        devices,
        profiles,
    )
    anomaly_dicts = [a.model_dump() for a in anomalies]

    critical = sum(1 for a in anomalies if a.threat_level == ThreatLevel.CRITICAL)
    high = sum(1 for a in anomalies if a.threat_level == ThreatLevel.HIGH)

    reasoning = f"Anomaly detection: {len(anomalies)} anomalies ({critical} critical, {high} high)"

    # LLM-enhanced behavior analysis
    try:
        from .prompts import (
            SYSTEM_BEHAVIOR_ANALYSIS,
            BehaviorAnalysisResult,
        )

        ctx = json.dumps(
            {
                "anomalies": anomaly_dicts[:15],
                "profiles_summary": profile_dicts[:10],
                "critical_count": critical,
                "high_count": high,
            },
            default=str,
        )
        llm_result = cast(
            BehaviorAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_BEHAVIOR_ANALYSIS,
                user_prompt=(f"IoT/OT behavior analysis:\n{ctx}"),
                schema=BehaviorAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="iot_ot_security",
            node="detect_anomalies",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="iot_ot_security",
            node="detect_anomalies",
        )

    return {
        "anomalies_detected": anomaly_dicts,
        "stage": "detect_anomalies",
        "current_step": "detect_anomalies",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def assess_vulnerabilities(
    state: dict[str, Any],
    toolkit: IoTOTSecurityToolkit,
) -> dict[str, Any]:
    """Assess firmware vulnerabilities on discovered devices."""
    logger.info(
        "iot_ot_security.node.assess_vulnerabilities",
    )
    state = _to_dict(state)
    device_dicts = state.get("devices_discovered", [])

    devices = [IoTDevice(**d) for d in device_dicts]
    vulns = await toolkit.assess_vulnerabilities(devices)
    vuln_dicts = [v.model_dump() for v in vulns]

    critical = sum(1 for v in vulns if v.severity == ThreatLevel.CRITICAL)
    exploitable = sum(1 for v in vulns if v.exploitable)
    no_patch = sum(1 for v in vulns if not v.patch_available)

    reasoning = (
        f"Vulnerability assessment: {len(vulns)} vulns "
        f"({critical} critical, {exploitable} "
        f"exploitable, {no_patch} unpatched)"
    )

    # LLM-enhanced vulnerability assessment
    try:
        from .prompts import (
            SYSTEM_VULNERABILITY_ASSESSMENT,
            VulnerabilityAssessmentResult,
        )

        ctx = json.dumps(
            {
                "vulnerabilities": vuln_dicts[:20],
                "critical_count": critical,
                "exploitable_count": exploitable,
                "unpatched_count": no_patch,
            },
            default=str,
        )
        llm_result = cast(
            VulnerabilityAssessmentResult,
            await llm_structured(
                system_prompt=(SYSTEM_VULNERABILITY_ASSESSMENT),
                user_prompt=(f"IoT/OT vuln assessment:\n{ctx}"),
                schema=VulnerabilityAssessmentResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="iot_ot_security",
            node="assess_vulnerabilities",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="iot_ot_security",
            node="assess_vulnerabilities",
        )

    return {
        "vulnerabilities_found": vuln_dicts,
        "stage": "assess_vulnerabilities",
        "current_step": "assess_vulnerabilities",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def enforce_segmentation(
    state: dict[str, Any],
    toolkit: IoTOTSecurityToolkit,
) -> dict[str, Any]:
    """Enforce micro-segmentation policies."""
    logger.info(
        "iot_ot_security.node.enforce_segmentation",
    )
    state = _to_dict(state)
    device_dicts = state.get("devices_discovered", [])
    anomaly_dicts = state.get("anomalies_detected", [])

    devices = [IoTDevice(**d) for d in device_dicts]
    anomalies = [DeviceAnomaly(**a) for a in anomaly_dicts]

    policies = await toolkit.enforce_segmentation(
        devices,
        anomalies,
    )
    policy_dicts = [p.model_dump() for p in policies]

    quarantined = sum(1 for p in policies if p.action == "quarantine")
    restricted = sum(1 for p in policies if p.action == "restrict")

    reasoning = (
        f"Segmentation: {len(policies)} policies "
        f"enforced ({quarantined} quarantined, "
        f"{restricted} restricted)"
    )

    return {
        "policies_enforced": policy_dicts,
        "stage": "enforce_segmentation",
        "current_step": "enforce_segmentation",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: IoTOTSecurityToolkit,
) -> dict[str, Any]:
    """Generate final IoT/OT security report."""
    logger.info("iot_ot_security.node.generate_report")
    state = _to_dict(state)
    session_start = state.get(
        "session_start",
        time.time(),
    )
    duration_ms = (time.time() - session_start) * 1000

    devices = state.get("devices_discovered", [])
    anomalies = state.get("anomalies_detected", [])
    vulns = state.get("vulnerabilities_found", [])
    policies = state.get("policies_enforced", [])
    unmanaged = state.get("unmanaged_devices", [])

    stats = state.get("stats", {})
    stats.update(
        {
            "total_devices": len(devices),
            "unmanaged_devices": len(unmanaged),
            "ai_connected_devices": sum(1 for d in devices if d.get("is_ai_connected")),
            "total_anomalies": len(anomalies),
            "critical_anomalies": sum(1 for a in anomalies if a.get("threat_level") == "critical"),
            "total_vulnerabilities": len(vulns),
            "critical_vulnerabilities": sum(1 for v in vulns if v.get("severity") == "critical"),
            "exploitable_vulnerabilities": sum(1 for v in vulns if v.get("exploitable")),
            "policies_enforced": len(policies),
            "devices_quarantined": sum(1 for p in policies if p.get("action") == "quarantine"),
            "devices_restricted": sum(1 for p in policies if p.get("action") == "restrict"),
        }
    )

    reasoning = (
        f"Report: {stats['total_devices']} devices, "
        f"{stats['total_anomalies']} anomalies, "
        f"{stats['total_vulnerabilities']} vulns, "
        f"{stats['policies_enforced']} policies"
    )

    return {
        "stats": stats,
        "stage": "report",
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }
