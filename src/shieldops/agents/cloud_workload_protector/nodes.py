"""Cloud Workload Protector Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CWPStage,
    RuntimeAnomaly,
    VulnerabilityFinding,
    WorkloadInventory,
    WorkloadSeverity,
)
from .tools import CloudWorkloadProtectorToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: CloudWorkloadProtectorToolkit | None = None


def _get_toolkit() -> CloudWorkloadProtectorToolkit:
    """Get module-level toolkit, creating default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = CloudWorkloadProtectorToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ---------------------------------------------------------------
# Node 1: scan_workloads
# ---------------------------------------------------------------
async def scan_workloads(
    state: dict[str, Any],
    toolkit: CloudWorkloadProtectorToolkit,
) -> dict[str, Any]:
    """Discover and inventory running workloads."""
    logger.info("cwp.node.scan_workloads")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    workloads = await toolkit.scan_workloads(tenant_id)
    workloads_data = [w.model_dump() for w in workloads]

    privileged = sum(1 for w in workloads if w.privileged)
    note = f"Scanned {len(workloads)} workloads, {privileged} privileged"

    return {
        "stage": CWPStage.DETECT_ANOMALIES.value,
        "workloads": workloads_data,
        "current_step": "scan_workloads",
        "reasoning_chain": (state.get("reasoning_chain", []) + [note]),
    }


# ---------------------------------------------------------------
# Node 2: detect_anomalies
# ---------------------------------------------------------------
async def detect_anomalies(
    state: dict[str, Any],
    toolkit: CloudWorkloadProtectorToolkit,
) -> dict[str, Any]:
    """Detect runtime anomalies across workloads."""
    logger.info("cwp.node.detect_anomalies")
    state = _to_dict(state)

    raw = state.get("workloads", [])
    workloads = [WorkloadInventory(**w) for w in raw]

    anomalies = await toolkit.detect_anomalies(workloads)
    anomalies_data = [a.model_dump() for a in anomalies]

    escapes = sum(1 for a in anomalies if a.container_escape)
    critical = sum(1 for a in anomalies if a.severity == WorkloadSeverity.CRITICAL)
    note = f"Detected {len(anomalies)} anomalies: {critical} critical, {escapes} container escapes"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_ANOMALY_DETECTION,
            AnomalyAnalysisOutput,
        )

        context = json.dumps(
            {
                "total_anomalies": len(anomalies),
                "critical": critical,
                "container_escapes": escapes,
                "anomalies": [
                    {
                        "type": a.anomaly_type,
                        "severity": a.severity.value,
                        "process": a.process,
                        "escape": a.container_escape,
                    }
                    for a in anomalies[:15]
                ],
            },
            default=str,
        )
        llm_result = cast(
            AnomalyAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_ANOMALY_DETECTION,
                user_prompt=(f"Runtime anomaly context:\n{context}"),
                schema=AnomalyAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cwp",
            node="detect_anomalies",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cwp",
            node="detect_anomalies",
        )

    return {
        "stage": CWPStage.ANALYZE_DRIFT.value,
        "anomalies": anomalies_data,
        "current_step": "detect_anomalies",
        "reasoning_chain": (state.get("reasoning_chain", []) + [note]),
    }


# ---------------------------------------------------------------
# Node 3: analyze_drift
# ---------------------------------------------------------------
async def analyze_drift(
    state: dict[str, Any],
    toolkit: CloudWorkloadProtectorToolkit,
) -> dict[str, Any]:
    """Analyze file integrity drift on workloads."""
    logger.info("cwp.node.analyze_drift")
    state = _to_dict(state)

    raw = state.get("workloads", [])
    workloads = [WorkloadInventory(**w) for w in raw]

    findings = await toolkit.analyze_drift(workloads)
    findings_data = [f.model_dump() for f in findings]

    critical = sum(1 for f in findings if f.severity == WorkloadSeverity.CRITICAL)
    note = f"Found {len(findings)} drift findings, {critical} critical"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_DRIFT_ANALYSIS,
            DriftAnalysisOutput,
        )

        context = json.dumps(
            {
                "total_findings": len(findings),
                "critical": critical,
                "findings": [
                    {
                        "file": f.file_path,
                        "type": f.change_type,
                        "severity": f.severity.value,
                    }
                    for f in findings[:15]
                ],
            },
            default=str,
        )
        llm_result = cast(
            DriftAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_DRIFT_ANALYSIS,
                user_prompt=(f"Drift analysis context:\n{context}"),
                schema=DriftAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cwp",
            node="analyze_drift",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cwp",
            node="analyze_drift",
        )

    return {
        "stage": CWPStage.ASSESS_VULNERABILITIES.value,
        "drift_findings": findings_data,
        "current_step": "analyze_drift",
        "reasoning_chain": (state.get("reasoning_chain", []) + [note]),
    }


# ---------------------------------------------------------------
# Node 4: assess_vulnerabilities
# ---------------------------------------------------------------
async def assess_vulnerabilities(
    state: dict[str, Any],
    toolkit: CloudWorkloadProtectorToolkit,
) -> dict[str, Any]:
    """Assess vulnerabilities in workload images."""
    logger.info("cwp.node.assess_vulnerabilities")
    state = _to_dict(state)

    raw = state.get("workloads", [])
    workloads = [WorkloadInventory(**w) for w in raw]

    vulns = await toolkit.assess_vulnerabilities(workloads)
    vulns_data = [v.model_dump() for v in vulns]

    critical = sum(1 for v in vulns if v.severity == WorkloadSeverity.CRITICAL)
    exploitable = sum(1 for v in vulns if v.exploitable)
    note = f"Found {len(vulns)} vulnerabilities: {critical} critical, {exploitable} exploitable"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_VULN_ASSESSMENT,
            VulnAssessmentOutput,
        )

        context = json.dumps(
            {
                "total_vulns": len(vulns),
                "critical": critical,
                "exploitable": exploitable,
                "top_vulns": [
                    {
                        "cve": v.cve_id,
                        "package": v.package_name,
                        "cvss": v.cvss_score,
                        "exploitable": v.exploitable,
                    }
                    for v in sorted(
                        vulns,
                        key=lambda x: x.cvss_score,
                        reverse=True,
                    )[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            VulnAssessmentOutput,
            await llm_structured(
                system_prompt=SYSTEM_VULN_ASSESSMENT,
                user_prompt=(f"Vulnerability context:\n{context}"),
                schema=VulnAssessmentOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cwp",
            node="assess_vulnerabilities",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cwp",
            node="assess_vulnerabilities",
        )

    return {
        "stage": CWPStage.CONTAIN_THREATS.value,
        "vulnerabilities": vulns_data,
        "current_step": "assess_vulnerabilities",
        "reasoning_chain": (state.get("reasoning_chain", []) + [note]),
    }


# ---------------------------------------------------------------
# Node 5: contain_threats
# ---------------------------------------------------------------
async def contain_threats(
    state: dict[str, Any],
    toolkit: CloudWorkloadProtectorToolkit,
) -> dict[str, Any]:
    """Contain threats via isolation, kill, quarantine."""
    logger.info("cwp.node.contain_threats")
    state = _to_dict(state)

    raw_anomalies = state.get("anomalies", [])
    anomalies = [RuntimeAnomaly(**a) for a in raw_anomalies]

    raw_vulns = state.get("vulnerabilities", [])
    vulns = [VulnerabilityFinding(**v) for v in raw_vulns]

    actions = await toolkit.contain_threats(
        anomalies,
        vulns,
    )
    actions_data = [a.model_dump() for a in actions]

    success = sum(1 for a in actions if a.success)
    note = f"Applied {len(actions)} containment actions, {success} successful"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_CONTAINMENT,
            ContainmentPlanOutput,
        )

        context = json.dumps(
            {
                "total_actions": len(actions),
                "successful": success,
                "action_types": [a.action_type for a in actions],
                "anomaly_count": len(anomalies),
                "vuln_count": len(vulns),
            },
            default=str,
        )
        llm_result = cast(
            ContainmentPlanOutput,
            await llm_structured(
                system_prompt=SYSTEM_CONTAINMENT,
                user_prompt=(f"Containment context:\n{context}"),
                schema=ContainmentPlanOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cwp",
            node="contain_threats",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cwp",
            node="contain_threats",
        )

    return {
        "stage": CWPStage.REPORT.value,
        "containment_actions": actions_data,
        "current_step": "contain_threats",
        "reasoning_chain": (state.get("reasoning_chain", []) + [note]),
    }


# ---------------------------------------------------------------
# Node 6: generate_report
# ---------------------------------------------------------------
async def generate_report(
    state: dict[str, Any],
    toolkit: CloudWorkloadProtectorToolkit,
) -> dict[str, Any]:
    """Generate the final workload protection report."""
    logger.info("cwp.node.generate_report")
    state = _to_dict(state)

    raw_workloads = state.get("workloads", [])
    raw_anomalies = state.get("anomalies", [])
    raw_drift = state.get("drift_findings", [])
    raw_vulns = state.get("vulnerabilities", [])
    raw_actions = state.get("containment_actions", [])

    # Severity distributions
    anomaly_sev: dict[str, int] = {}
    for a in raw_anomalies:
        sev = a.get("severity", "medium")
        anomaly_sev[sev] = anomaly_sev.get(sev, 0) + 1

    vuln_sev: dict[str, int] = {}
    for v in raw_vulns:
        sev = v.get("severity", "medium")
        vuln_sev[sev] = vuln_sev.get(sev, 0) + 1

    contained = sum(1 for a in raw_actions if a.get("success", False))

    # Compute protection score
    total_issues = len(raw_anomalies) + len(raw_drift) + len(raw_vulns)
    if total_issues > 0:
        score = max(
            0.0,
            100.0 - (total_issues * 2.5) + (contained * 5),
        )
        score = min(100.0, score)
    else:
        score = 100.0
    score = round(score, 1)

    elapsed = round(
        (time.time() - state.get("session_start", time.time())) * 1000,
        1,
    )

    stats = {
        "workloads_scanned": len(raw_workloads),
        "anomalies_detected": len(raw_anomalies),
        "anomaly_severity": anomaly_sev,
        "drift_findings": len(raw_drift),
        "vulnerabilities_found": len(raw_vulns),
        "vulnerability_severity": vuln_sev,
        "containment_actions": len(raw_actions),
        "containment_successful": contained,
        "protection_score": score,
    }

    report_summary = (
        f"Workload protection score: {score}/100. "
        f"{len(raw_workloads)} workloads, "
        f"{len(raw_anomalies)} anomalies, "
        f"{len(raw_drift)} drift findings, "
        f"{len(raw_vulns)} vulns, "
        f"{contained} contained."
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_REPORT,
            WorkloadReportOutput,
        )

        context = json.dumps(stats, default=str)
        llm_result = cast(
            WorkloadReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Workload protection stats:\n{context}"),
                schema=WorkloadReportOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cwp",
            node="generate_report",
        )
        report_summary = llm_result.summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cwp",
            node="generate_report",
        )

    return {
        "stage": CWPStage.REPORT.value,
        "stats": stats,
        "protection_score": score,
        "session_duration_ms": elapsed,
        "current_step": "generate_report",
        "reasoning_chain": (state.get("reasoning_chain", []) + [report_summary]),
    }
