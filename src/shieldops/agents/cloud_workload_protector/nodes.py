"""Cloud Workload Protector Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import CloudWorkload, WorkloadStage
from .tools import CloudWorkloadProtectorToolkit

logger = structlog.get_logger()

_toolkit: CloudWorkloadProtectorToolkit | None = None


def set_toolkit(
    toolkit: CloudWorkloadProtectorToolkit,
) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> CloudWorkloadProtectorToolkit:
    global _toolkit
    if _toolkit is None:
        _toolkit = CloudWorkloadProtectorToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def inventory_workloads(
    state: dict[str, Any],
    toolkit: CloudWorkloadProtectorToolkit,
) -> dict[str, Any]:
    """Inventory cloud workload instances."""
    logger.info("cwp.node.inventory")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    platforms = state.get("platforms", ["ec2"])

    workloads = await toolkit.inventory_workloads(tenant_id, platforms)
    workloads_data = [w.model_dump() for w in workloads]

    return {
        "stage": WorkloadStage.MONITOR_RUNTIME.value,
        "workloads": workloads_data,
        "current_step": "inventory_workloads",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Inventoried {len(workloads)} workloads across {', '.join(platforms)}"],
    }


async def monitor_runtime(
    state: dict[str, Any],
    toolkit: CloudWorkloadProtectorToolkit,
) -> dict[str, Any]:
    """Monitor runtime behavior for anomalies."""
    logger.info("cwp.node.runtime")
    state = _to_dict(state)

    raw_wls = state.get("workloads", [])
    workloads = [CloudWorkload(**w) for w in raw_wls]

    anomalies = await toolkit.monitor_runtime(workloads)
    anomalies_data = [a.model_dump() for a in anomalies]

    critical = sum(1 for a in anomalies if a.severity == "critical")
    reasoning_note = f"Detected {len(anomalies)} runtime anomalies, {critical} critical"

    try:
        from .prompts import (
            SYSTEM_RUNTIME_ANALYSIS,
            RuntimeAnalysisOutput,
        )

        context = json.dumps(
            {
                "anomalies": len(anomalies),
                "critical": critical,
                "types": list({a.anomaly_type for a in anomalies}),
            },
            default=str,
        )
        llm_result = cast(
            RuntimeAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_RUNTIME_ANALYSIS,
                user_prompt=f"Runtime context:\n{context}",
                schema=RuntimeAnalysisOutput,
            ),
        )
        logger.info("llm_enhanced", agent="cwp", node="runtime")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="cwp", node="runtime")

    return {
        "stage": WorkloadStage.DETECT_DRIFT.value,
        "runtime_anomalies": anomalies_data,
        "current_step": "monitor_runtime",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def detect_drift(
    state: dict[str, Any],
    toolkit: CloudWorkloadProtectorToolkit,
) -> dict[str, Any]:
    """Detect configuration drift from baselines."""
    logger.info("cwp.node.drift")
    state = _to_dict(state)

    raw_wls = state.get("workloads", [])
    workloads = [CloudWorkload(**w) for w in raw_wls]

    findings = await toolkit.detect_drift(workloads)
    findings_data = [f.model_dump() for f in findings]

    reasoning_note = (
        f"Found {len(findings)} drift findings,"
        f" {sum(1 for f in findings if f.auto_remediable)}"
        f" auto-fixable"
    )

    try:
        from .prompts import (
            SYSTEM_DRIFT_DETECTION,
            DriftAnalysisOutput,
        )

        context = json.dumps(
            {
                "drifts": len(findings),
                "auto_fixable": sum(1 for f in findings if f.auto_remediable),
            },
            default=str,
        )
        llm_result = cast(
            DriftAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_DRIFT_DETECTION,
                user_prompt=f"Drift context:\n{context}",
                schema=DriftAnalysisOutput,
            ),
        )
        logger.info("llm_enhanced", agent="cwp", node="drift")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="cwp", node="drift")

    return {
        "stage": WorkloadStage.SCAN_VULNERABILITIES.value,
        "drift_findings": findings_data,
        "current_step": "detect_drift",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def scan_vulnerabilities(
    state: dict[str, Any],
    toolkit: CloudWorkloadProtectorToolkit,
) -> dict[str, Any]:
    """Scan workloads for known vulnerabilities."""
    logger.info("cwp.node.vulns")
    state = _to_dict(state)

    raw_wls = state.get("workloads", [])
    workloads = [CloudWorkload(**w) for w in raw_wls]

    findings = await toolkit.scan_vulnerabilities(workloads)
    findings_data = [f.model_dump() for f in findings]

    return {
        "stage": WorkloadStage.ASSESS_RISK.value,
        "vulnerability_findings": findings_data,
        "current_step": "scan_vulnerabilities",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Found {len(findings)} vulnerabilities"],
    }


async def assess_risk(
    state: dict[str, Any],
    toolkit: CloudWorkloadProtectorToolkit,
) -> dict[str, Any]:
    """Assess overall workload protection risk."""
    logger.info("cwp.node.assess_risk")
    state = _to_dict(state)

    raw_wls = state.get("workloads", [])
    raw_anomalies = state.get("runtime_anomalies", [])
    raw_drift = state.get("drift_findings", [])
    raw_vulns = state.get("vulnerability_findings", [])

    all_scores = [a.get("risk_score", 0.0) for a in raw_anomalies]
    risk_score = round(max(all_scores) if all_scores else 0.0, 1)

    elapsed = round(
        (time.time() - state.get("session_start", time.time())) * 1000,
        1,
    )

    stats = {
        "workloads_scanned": len(raw_wls),
        "runtime_anomalies": len(raw_anomalies),
        "drift_findings": len(raw_drift),
        "vulnerabilities": len(raw_vulns),
        "risk_score": risk_score,
        "platforms": state.get("platforms", []),
    }

    report_summary = (
        f"CWP risk: {risk_score}/100."
        f" {len(raw_wls)} workloads,"
        f" {len(raw_anomalies)} anomalies,"
        f" {len(raw_drift)} drifts,"
        f" {len(raw_vulns)} vulns."
    )

    try:
        from .prompts import (
            SYSTEM_VULN_ASSESSMENT,
            VulnAssessmentOutput,
        )

        context = json.dumps(stats, default=str)
        llm_result = cast(
            VulnAssessmentOutput,
            await llm_structured(
                system_prompt=SYSTEM_VULN_ASSESSMENT,
                user_prompt=f"CWP context:\n{context}",
                schema=VulnAssessmentOutput,
            ),
        )
        logger.info("llm_enhanced", agent="cwp", node="risk")
        report_summary = llm_result.summary
    except Exception:
        logger.debug("llm_fallback", agent="cwp", node="risk")

    return {
        "stage": WorkloadStage.REPORT.value,
        "risk_score": risk_score,
        "stats": stats,
        "session_duration_ms": elapsed,
        "current_step": "assess_risk",
        "reasoning_chain": state.get("reasoning_chain", []) + [report_summary],
    }
