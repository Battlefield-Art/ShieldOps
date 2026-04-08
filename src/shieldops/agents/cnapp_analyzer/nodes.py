"""CNAPP Analyzer Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CNAPPStage,
    CodeVulnerability,
    EntitlementRisk,
    PostureFinding,
    SeverityLevel,
    WorkloadThreat,
)
from .tools import CNAPPAnalyzerToolkit

logger = structlog.get_logger()

# Module-level toolkit reference
_toolkit: CNAPPAnalyzerToolkit | None = None


def _get_toolkit() -> CNAPPAnalyzerToolkit:
    """Get the module-level toolkit."""
    global _toolkit
    if _toolkit is None:
        _toolkit = CNAPPAnalyzerToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: scan_cloud_posture
# ------------------------------------------------------------------
async def scan_cloud_posture(
    state: dict[str, Any],
    toolkit: CNAPPAnalyzerToolkit,
) -> dict[str, Any]:
    """Scan cloud posture with CIS benchmarks."""
    logger.info("cnapp_analyzer.node.scan_cloud_posture")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    providers = state.get("providers", ["aws"])
    frameworks = state.get("frameworks", ["cis"])

    findings = await toolkit.scan_cloud_posture(tenant_id, providers, frameworks)
    findings_data = [f.model_dump() for f in findings]

    fail_count = sum(1 for f in findings if f.status == "fail")
    crit_count = sum(
        1 for f in findings if f.status == "fail" and f.severity == SeverityLevel.CRITICAL
    )

    reasoning = (
        f"CSPM: scanned {len(findings)} controls, {fail_count} failing, {crit_count} critical"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_POSTURE_SCAN,
            PostureAnalysisOutput,
        )

        context = json.dumps(
            {
                "total": len(findings),
                "failing": fail_count,
                "critical": crit_count,
                "providers": providers,
                "top_failures": [
                    {
                        "control_id": f.control_id,
                        "control_name": f.control_name,
                        "severity": f.severity.value,
                        "provider": f.provider,
                    }
                    for f in findings
                    if f.status == "fail"
                ][:15],
            },
            default=str,
        )
        llm_result = cast(
            PostureAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_POSTURE_SCAN,
                user_prompt=(f"CSPM scan context:\n{context}"),
                schema=PostureAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cnapp_analyzer",
            node="scan_cloud_posture",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cnapp_analyzer",
            node="scan_cloud_posture",
        )

    return {
        "stage": CNAPPStage.ASSESS_WORKLOAD_PROTECTION.value,
        "posture_findings": findings_data,
        "current_step": "scan_cloud_posture",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


# ------------------------------------------------------------------
# Node 2: assess_workload_protection
# ------------------------------------------------------------------
async def assess_workload_protection(
    state: dict[str, Any],
    toolkit: CNAPPAnalyzerToolkit,
) -> dict[str, Any]:
    """Assess container and workload security."""
    logger.info("cnapp_analyzer.node.assess_workload_protection")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    providers = state.get("providers", ["aws"])

    threats = await toolkit.assess_workload_protection(tenant_id, providers)
    threats_data = [t.model_dump() for t in threats]

    crit = sum(1 for t in threats if t.severity == SeverityLevel.CRITICAL)
    runtime = sum(1 for t in threats if t.runtime_detected)

    reasoning = f"CWPP: {len(threats)} threats, {crit} critical, {runtime} runtime"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_WORKLOAD_ANALYSIS,
            WorkloadAnalysisOutput,
        )

        context = json.dumps(
            {
                "total_threats": len(threats),
                "critical": crit,
                "runtime_threats": runtime,
                "top_cves": [
                    {
                        "cve_id": t.cve_id,
                        "cvss": t.cvss_score,
                        "image": t.image,
                        "type": t.threat_type,
                    }
                    for t in sorted(
                        threats,
                        key=lambda x: x.cvss_score,
                        reverse=True,
                    )[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            WorkloadAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_WORKLOAD_ANALYSIS,
                user_prompt=(f"CWPP scan context:\n{context}"),
                schema=WorkloadAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cnapp_analyzer",
            node="assess_workload_protection",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cnapp_analyzer",
            node="assess_workload_protection",
        )

    return {
        "stage": CNAPPStage.ANALYZE_IDENTITY_ENTITLEMENTS.value,
        "workload_threats": threats_data,
        "current_step": "assess_workload_protection",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


# ------------------------------------------------------------------
# Node 3: analyze_identity_entitlements
# ------------------------------------------------------------------
async def analyze_identity_entitlements(
    state: dict[str, Any],
    toolkit: CNAPPAnalyzerToolkit,
) -> dict[str, Any]:
    """Analyze identity entitlements for CIEM risks."""
    logger.info("cnapp_analyzer.node.analyze_identity_entitlements")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    providers = state.get("providers", ["aws"])

    risks = await toolkit.analyze_identity_entitlements(tenant_id, providers)
    risks_data = [r.model_dump() for r in risks]

    over_priv = sum(1 for r in risks if r.unused_ratio > 0.7)
    crit = sum(1 for r in risks if r.severity == SeverityLevel.CRITICAL)

    reasoning = f"CIEM: {len(risks)} identities, {over_priv} over-privileged, {crit} critical"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_ENTITLEMENT_ANALYSIS,
            EntitlementAnalysisOutput,
        )

        context = json.dumps(
            {
                "total_identities": len(risks),
                "over_privileged": over_priv,
                "critical": crit,
                "top_risks": [
                    {
                        "type": r.identity_type,
                        "arn": r.identity_arn,
                        "unused": r.unused_ratio,
                        "risk_type": r.risk_type,
                    }
                    for r in sorted(
                        risks,
                        key=lambda x: x.unused_ratio,
                        reverse=True,
                    )[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            EntitlementAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_ENTITLEMENT_ANALYSIS,
                user_prompt=(f"CIEM analysis context:\n{context}"),
                schema=EntitlementAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cnapp_analyzer",
            node="analyze_identity_entitlements",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cnapp_analyzer",
            node="analyze_identity_entitlements",
        )

    return {
        "stage": CNAPPStage.SCAN_CODE_SECURITY.value,
        "entitlement_risks": risks_data,
        "current_step": "analyze_identity_entitlements",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


# ------------------------------------------------------------------
# Node 4: scan_code_security
# ------------------------------------------------------------------
async def scan_code_security(
    state: dict[str, Any],
    toolkit: CNAPPAnalyzerToolkit,
) -> dict[str, Any]:
    """Scan IaC and code for vulnerabilities."""
    logger.info("cnapp_analyzer.node.scan_code_security")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    providers = state.get("providers", ["aws"])

    vulns = await toolkit.scan_code_security(tenant_id, providers)
    vulns_data = [v.model_dump() for v in vulns]

    crit = sum(1 for v in vulns if v.severity == SeverityLevel.CRITICAL)
    high = sum(1 for v in vulns if v.severity == SeverityLevel.HIGH)

    reasoning = f"Code: {len(vulns)} IaC vulns, {crit} critical, {high} high"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_CODE_SECURITY,
            CodeSecurityOutput,
        )

        context = json.dumps(
            {
                "total_vulns": len(vulns),
                "critical": crit,
                "high": high,
                "top_vulns": [
                    {
                        "type": v.vuln_type,
                        "file": v.file_path,
                        "severity": v.severity.value,
                        "cwe": v.cwe_id,
                        "source": v.source_type,
                    }
                    for v in vulns
                    if v.severity
                    in (
                        SeverityLevel.CRITICAL,
                        SeverityLevel.HIGH,
                    )
                ][:10],
            },
            default=str,
        )
        llm_result = cast(
            CodeSecurityOutput,
            await llm_structured(
                system_prompt=SYSTEM_CODE_SECURITY,
                user_prompt=(f"Code security context:\n{context}"),
                schema=CodeSecurityOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cnapp_analyzer",
            node="scan_code_security",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cnapp_analyzer",
            node="scan_code_security",
        )

    return {
        "stage": CNAPPStage.CORRELATE_RISKS.value,
        "code_vulns": vulns_data,
        "current_step": "scan_code_security",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


# ------------------------------------------------------------------
# Node 5: correlate_risks
# ------------------------------------------------------------------
async def correlate_risks(
    state: dict[str, Any],
    toolkit: CNAPPAnalyzerToolkit,
) -> dict[str, Any]:
    """Correlate risks across all CNAPP domains."""
    logger.info("cnapp_analyzer.node.correlate_risks")
    state = _to_dict(state)

    posture = [PostureFinding(**f) for f in state.get("posture_findings", [])]
    workloads = [WorkloadThreat(**t) for t in state.get("workload_threats", [])]
    entitlements = [EntitlementRisk(**e) for e in state.get("entitlement_risks", [])]
    code = [CodeVulnerability(**v) for v in state.get("code_vulns", [])]
    frameworks = state.get("frameworks", ["cis"])

    score, compliance = await toolkit.correlate_risks(
        posture, workloads, entitlements, code, frameworks
    )

    reasoning = (
        f"Unified score: {score.overall_score}/100 "
        f"({score.risk_level}). "
        f"CSPM={score.cspm_score}, "
        f"CWPP={score.cwpp_score}, "
        f"CIEM={score.ciem_score}, "
        f"Code={score.code_security_score}"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_RISK_CORRELATION,
            UnifiedRiskOutput,
        )

        context = json.dumps(
            {
                "overall": score.overall_score,
                "cspm": score.cspm_score,
                "cwpp": score.cwpp_score,
                "ciem": score.ciem_score,
                "code": score.code_security_score,
                "attack_paths": score.attack_paths,
                "compliance": compliance,
                "posture_count": len(posture),
                "threat_count": len(workloads),
                "entitlement_count": len(entitlements),
                "code_vuln_count": len(code),
            },
            default=str,
        )
        llm_result = cast(
            UnifiedRiskOutput,
            await llm_structured(
                system_prompt=SYSTEM_RISK_CORRELATION,
                user_prompt=(f"Risk correlation:\n{context}"),
                schema=UnifiedRiskOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cnapp_analyzer",
            node="correlate_risks",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cnapp_analyzer",
            node="correlate_risks",
        )

    return {
        "stage": CNAPPStage.REPORT.value,
        "unified_risk_score": score.model_dump(),
        "compliance_coverage": compliance,
        "current_step": "correlate_risks",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


# ------------------------------------------------------------------
# Node 6: generate_report
# ------------------------------------------------------------------
async def generate_report(
    state: dict[str, Any],
    toolkit: CNAPPAnalyzerToolkit,
) -> dict[str, Any]:
    """Generate final CNAPP assessment report."""
    logger.info("cnapp_analyzer.node.generate_report")
    state = _to_dict(state)

    posture = state.get("posture_findings", [])
    workloads = state.get("workload_threats", [])
    entitlements = state.get("entitlement_risks", [])
    code_vulns = state.get("code_vulns", [])
    risk_score = state.get("unified_risk_score", {})
    compliance = state.get("compliance_coverage", {})

    # Severity distributions
    posture_sev: dict[str, int] = {}
    for f in posture:
        if f.get("status") == "fail":
            sev = f.get("severity", "medium")
            posture_sev[sev] = posture_sev.get(sev, 0) + 1

    threat_sev: dict[str, int] = {}
    for t in workloads:
        sev = t.get("severity", "medium")
        threat_sev[sev] = threat_sev.get(sev, 0) + 1

    elapsed = round(
        (time.time() - state.get("session_start", time.time())) * 1000,
        1,
    )

    stats = {
        "domains_scanned": [
            "cspm",
            "cwpp",
            "ciem",
            "code_security",
        ],
        "posture_findings": len(posture),
        "posture_failing": sum(1 for f in posture if f.get("status") == "fail"),
        "posture_severity": posture_sev,
        "workload_threats": len(workloads),
        "workload_severity": threat_sev,
        "runtime_threats": sum(1 for t in workloads if t.get("runtime_detected")),
        "entitlement_risks": len(entitlements),
        "over_privileged": sum(1 for e in entitlements if e.get("unused_ratio", 0) > 0.7),
        "code_vulns": len(code_vulns),
        "unified_risk_score": risk_score.get("overall_score", 0),
        "risk_level": risk_score.get("risk_level", "unknown"),
        "compliance_coverage": compliance,
        "providers": state.get("providers", []),
        "scan_duration_ms": elapsed,
    }

    reasoning = (
        f"CNAPP report: score "
        f"{risk_score.get('overall_score', 0)}/100, "
        f"{stats['posture_failing']} posture failures, "
        f"{stats['workload_threats']} workload threats, "
        f"{stats['over_privileged']} over-privileged, "
        f"{stats['code_vulns']} IaC vulns"
    )

    return {
        "stage": CNAPPStage.REPORT.value,
        "stats": stats,
        "session_duration_ms": elapsed,
        "current_step": "generate_report",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }
