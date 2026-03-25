"""Supply Chain Security Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import SupplyChainStage
from .tools import SupplyChainSecurityToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def generate_sbom(
    state: dict[str, Any],
    toolkit: SupplyChainSecurityToolkit,
) -> dict[str, Any]:
    """Generate Software Bill of Materials for target repositories."""
    logger.info("supply_chain.node.generate_sbom")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    repos = state.get("repositories", [])
    session_start = time.time()

    entries = await toolkit.generate_sbom(tenant_id=tenant_id, repos=repos or None)
    entry_dicts = [e.model_dump() for e in entries]

    ecosystems = list({e.ecosystem for e in entries})
    direct_count = sum(1 for e in entries if e.direct)

    return {
        "sbom_entries": entry_dicts,
        "stage": SupplyChainStage.SCAN_DEPENDENCIES.value,
        "session_start": session_start,
        "current_step": "generate_sbom",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Generated SBOM: {len(entries)} packages ({direct_count} direct) across {ecosystems}"],
    }


async def scan_dependencies(
    state: dict[str, Any],
    toolkit: SupplyChainSecurityToolkit,
) -> dict[str, Any]:
    """Scan dependencies for known vulnerabilities."""
    logger.info("supply_chain.node.scan_dependencies")
    state = _to_dict(state)

    from .models import SBOMEntry

    raw_entries = state.get("sbom_entries", [])
    sbom = [SBOMEntry(**e) for e in raw_entries]

    vulns = await toolkit.scan_dependencies(sbom)
    vuln_dicts = [v.model_dump() for v in vulns]

    reasoning_note = f"Scanned {len(sbom)} packages: {len(vulns)} vulnerabilities found"

    # LLM enhancement: deeper vulnerability analysis
    try:
        from .prompts import SYSTEM_VULNERABILITY_ANALYSIS, VulnerabilityAnalysisResult

        analysis_context = json.dumps(
            {
                "sbom_count": len(sbom),
                "vulnerability_count": len(vulns),
                "critical_vulns": [v.model_dump() for v in vulns if v.severity == "critical"],
                "exploitable_vulns": [v.model_dump() for v in vulns if v.exploitable],
            },
            default=str,
        )
        llm_result = cast(
            VulnerabilityAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_VULNERABILITY_ANALYSIS,
                user_prompt=f"Vulnerability scan results:\n{analysis_context}",
                schema=VulnerabilityAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="supply_chain_security",
            node="scan_dependencies",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="supply_chain_security",
            node="scan_dependencies",
        )

    return {
        "dependency_vulnerabilities": vuln_dicts,
        "stage": SupplyChainStage.AUDIT_CICD.value,
        "current_step": "scan_dependencies",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def audit_cicd(
    state: dict[str, Any],
    toolkit: SupplyChainSecurityToolkit,
) -> dict[str, Any]:
    """Audit CI/CD pipelines for security threats."""
    logger.info("supply_chain.node.audit_cicd")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")

    findings = await toolkit.audit_cicd_pipelines(tenant_id=tenant_id)
    finding_dicts = [f.model_dump() for f in findings]

    reasoning_note = f"Audited CI/CD pipelines: {len(findings)} threats found"

    # LLM enhancement: pipeline security analysis
    try:
        from .prompts import SYSTEM_PIPELINE_SECURITY, PipelineSecurityResult

        pipeline_context = json.dumps(
            {
                "finding_count": len(findings),
                "findings_summary": finding_dicts[:15],
                "threat_types": list({f.threat_type.value for f in findings}),
                "severity_distribution": {
                    sev: sum(1 for f in findings if f.severity == sev)
                    for sev in ("critical", "high", "medium", "low")
                },
            },
            default=str,
        )
        llm_result = cast(
            PipelineSecurityResult,
            await llm_structured(
                system_prompt=SYSTEM_PIPELINE_SECURITY,
                user_prompt=f"Pipeline audit results:\n{pipeline_context}",
                schema=PipelineSecurityResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="supply_chain_security",
            node="audit_cicd",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="supply_chain_security",
            node="audit_cicd",
        )

    return {
        "pipeline_findings": finding_dicts,
        "stage": SupplyChainStage.VERIFY_SIGNATURES.value,
        "current_step": "audit_cicd",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def verify_signatures(
    state: dict[str, Any],
    toolkit: SupplyChainSecurityToolkit,
) -> dict[str, Any]:
    """Verify artifact signatures and trust chains."""
    logger.info("supply_chain.node.verify_signatures")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")

    verifications = await toolkit.verify_signatures(tenant_id=tenant_id)
    verification_dicts = [v.model_dump() for v in verifications]

    signed_count = sum(1 for v in verifications if v.signed)
    trusted_count = sum(1 for v in verifications if v.trust_chain_valid)
    unsigned_count = len(verifications) - signed_count

    return {
        "signature_verifications": verification_dicts,
        "stage": SupplyChainStage.ASSESS_RISK.value,
        "current_step": "verify_signatures",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Verified {len(verifications)} artifacts: "
            f"{signed_count} signed, {trusted_count} trusted, "
            f"{unsigned_count} unsigned"
        ],
    }


async def assess_risk(
    state: dict[str, Any],
    toolkit: SupplyChainSecurityToolkit,
) -> dict[str, Any]:
    """Assess overall supply chain risk from all findings."""
    logger.info("supply_chain.node.assess_risk")
    state = _to_dict(state)

    vulns = state.get("dependency_vulnerabilities", [])
    findings = state.get("pipeline_findings", [])
    sigs = state.get("signature_verifications", [])
    sbom = state.get("sbom_entries", [])

    # Compute composite risk score
    vuln_score = 0.0
    for v in vulns:
        cvss = v.get("cvss_score", 0.0)
        exploitable = v.get("exploitable", False)
        weight = 1.5 if exploitable else 1.0
        vuln_score += (cvss / 10.0) * weight
    vuln_score = min(vuln_score / max(len(sbom), 1), 1.0)

    pipeline_score = 0.0
    severity_weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.1}
    for f in findings:
        pipeline_score += severity_weights.get(f.get("severity", "medium"), 0.3)
    pipeline_score = min(pipeline_score / max(len(findings), 1) if findings else 0.0, 1.0)

    unsigned_ratio = sum(1 for s in sigs if not s.get("signed", False)) / max(len(sigs), 1)

    # Weighted composite: vulns 40%, pipeline 35%, signing 25%
    risk_score = round(
        vuln_score * 0.40 + pipeline_score * 0.35 + unsigned_ratio * 0.25,
        4,
    )

    stats = {
        "total_packages": len(sbom),
        "total_vulnerabilities": len(vulns),
        "critical_vulnerabilities": sum(1 for v in vulns if v.get("severity") == "critical"),
        "exploitable_vulnerabilities": sum(1 for v in vulns if v.get("exploitable", False)),
        "pipeline_threats": len(findings),
        "unsigned_artifacts": sum(1 for s in sigs if not s.get("signed", False)),
        "total_artifacts": len(sigs),
        "vuln_subscore": round(vuln_score, 4),
        "pipeline_subscore": round(pipeline_score, 4),
        "signing_subscore": round(unsigned_ratio, 4),
    }

    reasoning_note = (
        f"Risk assessment: score={risk_score} "
        f"(vuln={vuln_score:.2f}, pipeline={pipeline_score:.2f}, "
        f"signing={unsigned_ratio:.2f})"
    )

    # LLM enhancement: comprehensive risk assessment
    try:
        from .prompts import SYSTEM_RISK_ASSESSMENT, SupplyChainRiskResult

        risk_context = json.dumps(
            {
                "stats": stats,
                "critical_vulns": [v for v in vulns if v.get("severity") == "critical"][:10],
                "pipeline_threats": findings[:10],
                "unsigned_artifacts": [s for s in sigs if not s.get("signed", False)],
            },
            default=str,
        )
        llm_result = cast(
            SupplyChainRiskResult,
            await llm_structured(
                system_prompt=SYSTEM_RISK_ASSESSMENT,
                user_prompt=f"Supply chain risk data:\n{risk_context}",
                schema=SupplyChainRiskResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="supply_chain_security",
            node="assess_risk",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
        # Use LLM risk score if it provides stronger signal
        if llm_result.risk_score > 0:
            risk_score = round((risk_score + llm_result.risk_score) / 2, 4)
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="supply_chain_security",
            node="assess_risk",
        )

    return {
        "risk_score": risk_score,
        "stats": stats,
        "stage": SupplyChainStage.REPORT.value,
        "current_step": "assess_risk",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: SupplyChainSecurityToolkit,
) -> dict[str, Any]:
    """Generate final supply chain security report."""
    logger.info("supply_chain.node.generate_report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    stats = state.get("stats", {})
    risk_score = state.get("risk_score", 0.0)

    return {
        "current_step": "report",
        "stage": SupplyChainStage.REPORT.value,
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report complete: {stats.get('total_packages', 0)} packages scanned, "
            f"{stats.get('total_vulnerabilities', 0)} vulns, "
            f"{stats.get('pipeline_threats', 0)} pipeline threats, "
            f"{stats.get('unsigned_artifacts', 0)} unsigned artifacts, "
            f"risk_score={risk_score}"
        ],
    }
