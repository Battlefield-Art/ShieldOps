"""Cloud Posture Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    BenchmarkResult,
    CloudResource,
    Misconfiguration,
    PostureStage,
    SeverityLevel,
)
from .tools import CloudPostureToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: CloudPostureToolkit | None = None


def set_toolkit(toolkit: CloudPostureToolkit) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> CloudPostureToolkit:
    """Get the module-level toolkit, creating a default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = CloudPostureToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: scan_cloud
# ------------------------------------------------------------------
async def scan_cloud(state: dict[str, Any], toolkit: CloudPostureToolkit) -> dict[str, Any]:
    """Enumerate cloud resources across requested providers."""
    logger.info("cloud_posture.node.scan_cloud")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    providers = state.get("providers", ["aws"])

    resources = await toolkit.scan_cloud_resources(tenant_id, providers)
    resources_data = [r.model_dump() for r in resources]

    return {
        "stage": PostureStage.ASSESS_BENCHMARKS.value,
        "cloud_resources": resources_data,
        "current_step": "scan_cloud",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Scanned {len(resources)} resources across {', '.join(providers)}"],
    }


# ------------------------------------------------------------------
# Node 2: assess_benchmarks
# ------------------------------------------------------------------
async def assess_benchmarks(state: dict[str, Any], toolkit: CloudPostureToolkit) -> dict[str, Any]:
    """Evaluate CIS/NIST controls against discovered resources."""
    logger.info("cloud_posture.node.assess_benchmarks")
    state = _to_dict(state)

    raw_resources = state.get("cloud_resources", [])
    resources = [CloudResource(**r) for r in raw_resources]
    frameworks = state.get("frameworks", ["cis_aws"])

    results = await toolkit.assess_benchmarks(resources, frameworks)
    results_data = [r.model_dump() for r in results]

    pass_count = sum(1 for r in results if r.status == "pass")
    fail_count = sum(1 for r in results if r.status == "fail")
    warn_count = sum(1 for r in results if r.status == "warn")

    reasoning_note = (
        f"Assessed {len(results)} controls: {pass_count} pass, {fail_count} fail, {warn_count} warn"
    )

    # LLM enhancement: intelligent benchmark analysis
    try:
        from .prompts import SYSTEM_BENCHMARK_ASSESSMENT, BenchmarkOutput

        context = json.dumps(
            {
                "total_controls": len(results),
                "pass": pass_count,
                "fail": fail_count,
                "warn": warn_count,
                "frameworks": frameworks,
                "failing_controls": [
                    {
                        "control_id": r.control_id,
                        "control_name": r.control_name,
                        "severity": r.severity.value
                        if hasattr(r.severity, "value")
                        else str(r.severity),
                    }
                    for r in results
                    if r.status == "fail"
                ][:20],
            },
            default=str,
        )
        llm_result = cast(
            BenchmarkOutput,
            await llm_structured(
                system_prompt=SYSTEM_BENCHMARK_ASSESSMENT,
                user_prompt=f"Benchmark assessment context:\n{context}",
                schema=BenchmarkOutput,
            ),
        )
        logger.info("llm_enhanced", agent="cloud_posture", node="assess_benchmarks")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="cloud_posture", node="assess_benchmarks")

    return {
        "stage": PostureStage.DETECT_MISCONFIGS.value,
        "benchmark_results": results_data,
        "current_step": "assess_benchmarks",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Node 3: detect_misconfigs
# ------------------------------------------------------------------
async def detect_misconfigs(state: dict[str, Any], toolkit: CloudPostureToolkit) -> dict[str, Any]:
    """Extract actionable misconfigurations from failing benchmarks."""
    logger.info("cloud_posture.node.detect_misconfigs")
    state = _to_dict(state)

    raw_results = state.get("benchmark_results", [])
    results = [BenchmarkResult(**r) for r in raw_results]

    misconfigs = await toolkit.detect_misconfigurations(results)
    misconfigs_data = [m.model_dump() for m in misconfigs]

    critical = sum(1 for m in misconfigs if m.severity == SeverityLevel.CRITICAL)
    high = sum(1 for m in misconfigs if m.severity == SeverityLevel.HIGH)

    reasoning_note = (
        f"Detected {len(misconfigs)} misconfigurations: {critical} critical, {high} high"
    )

    # LLM enhancement: misconfig analysis
    try:
        from .prompts import SYSTEM_MISCONFIG_DETECTION, MisconfigOutput

        context = json.dumps(
            {
                "total_misconfigs": len(misconfigs),
                "critical": critical,
                "high": high,
                "auto_remediable": sum(1 for m in misconfigs if m.auto_remediable),
                "top_misconfigs": [
                    {
                        "type": m.misconfig_type,
                        "severity": m.severity.value
                        if hasattr(m.severity, "value")
                        else str(m.severity),
                        "risk_score": m.risk_score,
                        "cis_ref": m.cis_reference,
                    }
                    for m in sorted(misconfigs, key=lambda x: x.risk_score, reverse=True)[:15]
                ],
            },
            default=str,
        )
        llm_result = cast(
            MisconfigOutput,
            await llm_structured(
                system_prompt=SYSTEM_MISCONFIG_DETECTION,
                user_prompt=f"Misconfiguration context:\n{context}",
                schema=MisconfigOutput,
            ),
        )
        logger.info("llm_enhanced", agent="cloud_posture", node="detect_misconfigs")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="cloud_posture", node="detect_misconfigs")

    return {
        "stage": PostureStage.PRIORITIZE_RISKS.value,
        "misconfigurations": misconfigs_data,
        "current_step": "detect_misconfigs",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Node 4: prioritize_risks
# ------------------------------------------------------------------
async def prioritize_risks(state: dict[str, Any], toolkit: CloudPostureToolkit) -> dict[str, Any]:
    """Prioritize misconfigurations by risk score and severity."""
    logger.info("cloud_posture.node.prioritize_risks")
    state = _to_dict(state)

    raw_misconfigs = state.get("misconfigurations", [])
    misconfigs = [Misconfiguration(**m) for m in raw_misconfigs]

    # Sort by risk_score descending, then severity weight
    severity_weight = {
        SeverityLevel.CRITICAL: 5,
        SeverityLevel.HIGH: 4,
        SeverityLevel.MEDIUM: 3,
        SeverityLevel.LOW: 2,
        SeverityLevel.INFO: 1,
    }
    prioritized = sorted(
        misconfigs,
        key=lambda m: (
            severity_weight.get(m.severity, 0),
            m.risk_score,
        ),
        reverse=True,
    )
    prioritized_data = [m.model_dump() for m in prioritized]

    # Compute posture score
    raw_results = state.get("benchmark_results", [])
    total = len(raw_results) if raw_results else 1
    passing = sum(1 for r in raw_results if r.get("status") == "pass")
    posture_score = round((passing / total) * 100.0, 1)

    return {
        "stage": PostureStage.PRIORITIZE_RISKS.value,
        "misconfigurations": prioritized_data,
        "posture_score": posture_score,
        "current_step": "prioritize_risks",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Prioritized {len(prioritized)} misconfigs, posture score: {posture_score}/100"],
    }


# ------------------------------------------------------------------
# Node 5: remediate
# ------------------------------------------------------------------
async def remediate(state: dict[str, Any], toolkit: CloudPostureToolkit) -> dict[str, Any]:
    """Auto-remediate misconfigurations that support automated fixes."""
    logger.info("cloud_posture.node.remediate")
    state = _to_dict(state)

    raw_misconfigs = state.get("misconfigurations", [])
    misconfigs = [Misconfiguration(**m) for m in raw_misconfigs]

    actions = await toolkit.remediate_misconfigs(misconfigs)
    actions_data = [a.model_dump() for a in actions]

    success_count = sum(1 for a in actions if a.success)

    reasoning_note = f"Applied {len(actions)} remediations, {success_count} successful"

    # LLM enhancement: remediation planning
    try:
        from .prompts import SYSTEM_REMEDIATION_PLANNING, RemediationPlanOutput

        manual_misconfigs = [m for m in misconfigs if not m.auto_remediable]
        context = json.dumps(
            {
                "total_misconfigs": len(misconfigs),
                "auto_remediated": len(actions),
                "success": success_count,
                "manual_required": len(manual_misconfigs),
                "manual_items": [
                    {
                        "type": m.misconfig_type,
                        "severity": m.severity.value
                        if hasattr(m.severity, "value")
                        else str(m.severity),
                        "cis_ref": m.cis_reference,
                    }
                    for m in manual_misconfigs[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RemediationPlanOutput,
            await llm_structured(
                system_prompt=SYSTEM_REMEDIATION_PLANNING,
                user_prompt=f"Remediation context:\n{context}",
                schema=RemediationPlanOutput,
            ),
        )
        logger.info("llm_enhanced", agent="cloud_posture", node="remediate")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="cloud_posture", node="remediate")

    return {
        "stage": PostureStage.REPORT.value,
        "remediation_actions": actions_data,
        "current_step": "remediate",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Node 6: generate_report
# ------------------------------------------------------------------
async def generate_report(state: dict[str, Any], toolkit: CloudPostureToolkit) -> dict[str, Any]:
    """Generate the final CSPM posture report with stats and score."""
    logger.info("cloud_posture.node.generate_report")
    state = _to_dict(state)

    raw_resources = state.get("cloud_resources", [])
    raw_results = state.get("benchmark_results", [])
    raw_misconfigs = state.get("misconfigurations", [])
    raw_actions = state.get("remediation_actions", [])
    posture_score = state.get("posture_score", 0.0)

    # Compute summary statistics
    total_controls = len(raw_results)
    pass_count = sum(1 for r in raw_results if r.get("status") == "pass")
    fail_count = sum(1 for r in raw_results if r.get("status") == "fail")

    severity_dist: dict[str, int] = {}
    for m in raw_misconfigs:
        sev = m.get("severity", "medium")
        severity_dist[sev] = severity_dist.get(sev, 0) + 1

    remediated_count = sum(1 for a in raw_actions if a.get("success", False))

    elapsed = round((time.time() - state.get("session_start", time.time())) * 1000, 1)

    stats = {
        "resources_scanned": len(raw_resources),
        "controls_evaluated": total_controls,
        "controls_passing": pass_count,
        "controls_failing": fail_count,
        "compliance_rate": round((pass_count / total_controls * 100) if total_controls else 0.0, 1),
        "misconfigurations_found": len(raw_misconfigs),
        "severity_distribution": severity_dist,
        "auto_remediated": remediated_count,
        "posture_score": posture_score,
        "providers": state.get("providers", []),
    }

    # LLM enhancement: posture analysis summary
    report_summary = (
        f"Cloud posture score: {posture_score}/100. "
        f"{len(raw_resources)} resources, {total_controls} controls, "
        f"{len(raw_misconfigs)} misconfigs, {remediated_count} remediated."
    )
    try:
        from .prompts import SYSTEM_POSTURE_ANALYSIS, PostureAnalysisOutput

        context = json.dumps(stats, default=str)
        llm_result = cast(
            PostureAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_POSTURE_ANALYSIS,
                user_prompt=f"Posture stats:\n{context}",
                schema=PostureAnalysisOutput,
            ),
        )
        logger.info("llm_enhanced", agent="cloud_posture", node="generate_report")
        report_summary = llm_result.summary
    except Exception:
        logger.debug("llm_fallback", agent="cloud_posture", node="generate_report")

    return {
        "stage": PostureStage.REPORT.value,
        "stats": stats,
        "posture_score": posture_score,
        "session_duration_ms": elapsed,
        "current_step": "generate_report",
        "reasoning_chain": state.get("reasoning_chain", []) + [report_summary],
    }
