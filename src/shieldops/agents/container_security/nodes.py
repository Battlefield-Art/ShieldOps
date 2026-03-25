"""Container Security Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    ImageSeverity,
    ImageVulnerability,
    RuntimeAnomaly,
)
from .tools import ContainerSecurityToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def scan_images(
    state: dict[str, Any],
    toolkit: ContainerSecurityToolkit,
) -> dict[str, Any]:
    """Scan container images for known vulnerabilities."""
    logger.info("container_security.node.scan_images")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    namespaces = state.get("namespaces", ["default"])
    session_start = time.time()

    vulns = await toolkit.scan_images(tenant_id=tenant_id, namespaces=namespaces)
    vuln_dicts = [v.model_dump() for v in vulns]

    critical = sum(1 for v in vulns if v.severity == ImageSeverity.CRITICAL)
    high = sum(1 for v in vulns if v.severity == ImageSeverity.HIGH)
    exploitable = sum(1 for v in vulns if v.exploitable)

    reasoning_note = (
        f"Scanned {len(namespaces)} namespaces: {len(vulns)} vulns found "
        f"({critical} critical, {high} high, {exploitable} exploitable)"
    )

    # LLM-enhanced vulnerability triage
    try:
        from .prompts import SYSTEM_VULNERABILITY_ANALYSIS, VulnerabilityAnalysisResult

        scan_context = json.dumps(
            {
                "tenant_id": tenant_id,
                "namespaces": namespaces,
                "total_vulns": len(vulns),
                "critical_count": critical,
                "high_count": high,
                "exploitable_count": exploitable,
                "vulns_summary": vuln_dicts[:20],
            },
            default=str,
        )
        llm_result = cast(
            VulnerabilityAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_VULNERABILITY_ANALYSIS,
                user_prompt=f"Container image scan results:\n{scan_context}",
                schema=VulnerabilityAnalysisResult,
            ),
        )
        logger.info("llm_enhanced", agent="container_security", node="scan_images")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="container_security", node="scan_images")

    return {
        "image_vulnerabilities": vuln_dicts,
        "session_start": session_start,
        "stage": "scan_images",
        "current_step": "scan_images",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def analyze_runtime(
    state: dict[str, Any],
    toolkit: ContainerSecurityToolkit,
) -> dict[str, Any]:
    """Analyze Kubernetes runtime for container threats."""
    logger.info("container_security.node.analyze_runtime")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    namespaces = state.get("namespaces", ["default"])

    anomalies = await toolkit.analyze_runtime(tenant_id=tenant_id, namespaces=namespaces)
    anomaly_dicts = [a.model_dump() for a in anomalies]

    reasoning_note = (
        f"Runtime analysis: {len(anomalies)} anomalies detected across {len(namespaces)} namespaces"
    )

    return {
        "runtime_anomalies": anomaly_dicts,
        "stage": "analyze_runtime",
        "current_step": "analyze_runtime",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def detect_anomalies(
    state: dict[str, Any],
    toolkit: ContainerSecurityToolkit,
) -> dict[str, Any]:
    """Correlate and assess runtime anomalies using LLM analysis."""
    logger.info("container_security.node.detect_anomalies")
    state = _to_dict(state)
    anomaly_dicts = state.get("runtime_anomalies", [])
    vuln_dicts = state.get("image_vulnerabilities", [])

    # Cross-correlate: pods with both runtime threats AND image vulns
    vuln_images = {v.get("image", "") for v in vuln_dicts}
    correlated: list[dict[str, Any]] = []
    for anomaly in anomaly_dicts:
        pod = anomaly.get("pod_name", "")
        for v in vuln_dicts:
            if pod in v.get("image", ""):
                correlated.append({"anomaly_id": anomaly.get("id"), "vuln_id": v.get("id")})

    reasoning_note = (
        f"Anomaly correlation: {len(correlated)} cross-references between "
        f"{len(anomaly_dicts)} runtime anomalies and {len(vuln_dicts)} vulns"
    )

    # LLM threat correlation
    try:
        from .prompts import SYSTEM_RUNTIME_THREAT_ANALYSIS, RuntimeThreatAnalysisResult

        threat_context = json.dumps(
            {
                "runtime_anomalies": anomaly_dicts[:15],
                "image_vulns_summary": vuln_dicts[:10],
                "correlated_findings": correlated[:10],
                "vuln_images": list(vuln_images)[:10],
            },
            default=str,
        )
        llm_result = cast(
            RuntimeThreatAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_RUNTIME_THREAT_ANALYSIS,
                user_prompt=f"Runtime threat data:\n{threat_context}",
                schema=RuntimeThreatAnalysisResult,
            ),
        )
        logger.info("llm_enhanced", agent="container_security", node="detect_anomalies")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="container_security", node="detect_anomalies")

    stats = state.get("stats", {})
    stats["correlated_findings"] = len(correlated)

    return {
        "stats": stats,
        "stage": "detect_anomalies",
        "current_step": "detect_anomalies",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def enforce_admission(
    state: dict[str, Any],
    toolkit: ContainerSecurityToolkit,
) -> dict[str, Any]:
    """Evaluate images against admission control policies."""
    logger.info("container_security.node.enforce_admission")
    state = _to_dict(state)
    vuln_dicts = state.get("image_vulnerabilities", [])

    # Collect unique images and their critical CVEs
    images: set[str] = set()
    critical_cves_by_image: dict[str, list[str]] = {}
    for v in vuln_dicts:
        img = v.get("image", "")
        tag = v.get("tag", "latest")
        full_img = f"{img}:{tag}"
        images.add(full_img)
        if v.get("severity") == ImageSeverity.CRITICAL.value:
            critical_cves_by_image.setdefault(full_img, []).append(v.get("cve_id", ""))

    image_list = sorted(images)
    decisions = await toolkit.enforce_admission(
        images=image_list,
        critical_cves=[cve for cves in critical_cves_by_image.values() for cve in cves][:5],
    )
    decision_dicts = [d.model_dump() for d in decisions]

    denied = sum(1 for d in decisions if d.decision == "deny")
    warned = sum(1 for d in decisions if d.decision == "warn")

    reasoning_note = (
        f"Admission control: {len(decisions)} images evaluated, {denied} denied, {warned} warned"
    )

    # LLM policy gap analysis
    try:
        from .prompts import SYSTEM_ADMISSION_POLICY, AdmissionPolicyResult

        policy_context = json.dumps(
            {
                "decisions": decision_dicts[:20],
                "critical_cves_by_image": {
                    k: v for k, v in list(critical_cves_by_image.items())[:10]
                },
                "denied_count": denied,
                "warned_count": warned,
            },
            default=str,
        )
        llm_result = cast(
            AdmissionPolicyResult,
            await llm_structured(
                system_prompt=SYSTEM_ADMISSION_POLICY,
                user_prompt=f"Admission evaluation results:\n{policy_context}",
                schema=AdmissionPolicyResult,
            ),
        )
        logger.info("llm_enhanced", agent="container_security", node="enforce_admission")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="container_security", node="enforce_admission")

    return {
        "admission_decisions": decision_dicts,
        "stage": "enforce_admission",
        "current_step": "enforce_admission",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def remediate(
    state: dict[str, Any],
    toolkit: ContainerSecurityToolkit,
) -> dict[str, Any]:
    """Remediate critical runtime threats and vulnerabilities."""
    logger.info("container_security.node.remediate")
    state = _to_dict(state)
    anomaly_dicts = state.get("runtime_anomalies", [])
    vuln_dicts = state.get("image_vulnerabilities", [])

    # Reconstruct typed models for the toolkit
    anomalies = [RuntimeAnomaly(**a) for a in anomaly_dicts]
    vulns = [ImageVulnerability(**v) for v in vuln_dicts]

    actions = await toolkit.remediate_containers(anomalies=anomalies, vulns=vulns)
    action_dicts = [a.model_dump() for a in actions]

    successful = sum(1 for a in actions if a.success)
    reasoning_note = f"Remediation: {len(actions)} actions taken, {successful} successful"

    return {
        "remediation_actions": action_dicts,
        "stage": "remediate",
        "current_step": "remediate",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: ContainerSecurityToolkit,
) -> dict[str, Any]:
    """Generate final container security report."""
    logger.info("container_security.node.generate_report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    vulns = state.get("image_vulnerabilities", [])
    anomalies = state.get("runtime_anomalies", [])
    decisions = state.get("admission_decisions", [])
    remediations = state.get("remediation_actions", [])

    stats = state.get("stats", {})
    stats.update(
        {
            "total_vulnerabilities": len(vulns),
            "critical_vulnerabilities": sum(1 for v in vulns if v.get("severity") == "critical"),
            "exploitable_vulnerabilities": sum(1 for v in vulns if v.get("exploitable")),
            "runtime_anomalies": len(anomalies),
            "images_denied": sum(1 for d in decisions if d.get("decision") == "deny"),
            "images_warned": sum(1 for d in decisions if d.get("decision") == "warn"),
            "remediations_applied": sum(1 for r in remediations if r.get("applied")),
            "remediations_successful": sum(1 for r in remediations if r.get("success")),
        }
    )

    reasoning_note = (
        f"Report: {stats['total_vulnerabilities']} vulns, "
        f"{stats['runtime_anomalies']} anomalies, "
        f"{stats['images_denied']} denied, "
        f"{stats['remediations_applied']} remediations"
    )

    return {
        "stats": stats,
        "stage": "report",
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }
