"""Code Security Scanner Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CodeScanResult,
    DependencyScanResult,
    IaCScanResult,
    ScanStage,
)
from .tools import CodeSecurityScannerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict safely."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_repositories(
    state: dict[str, Any],
    toolkit: CodeSecurityScannerToolkit,
) -> dict[str, Any]:
    """Discover repositories and code targets to scan."""
    logger.info("code_security_scanner.node.discover_repos")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    targets = state.get("scan_targets", [])
    session_start = time.time()

    repos = await toolkit.discover_repositories(tenant_id=tenant_id, targets=targets)
    repo_dicts = [r.model_dump() for r in repos]
    iac_count = sum(1 for r in repos if r.has_iac)
    ai_count = sum(1 for r in repos if r.has_ai_code)

    return {
        "repos_scanned": repo_dicts,
        "stage": ScanStage.DISCOVER_REPOSITORIES.value,
        "session_start": session_start,
        "current_step": "discover_repositories",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(repos)} repos: {iac_count} with IaC, {ai_count} with AI code"],
    }


async def scan_iac(
    state: dict[str, Any],
    toolkit: CodeSecurityScannerToolkit,
) -> dict[str, Any]:
    """Scan IaC files for misconfigurations."""
    logger.info("code_security_scanner.node.scan_iac")
    state = _to_dict(state)
    targets = state.get("scan_targets", [])

    from .models import Repository

    raw_repos = state.get("repos_scanned", [])
    repos = [Repository(**r) if isinstance(r, dict) else r for r in raw_repos]

    findings = await toolkit.scan_iac(repos, targets)
    finding_dicts = [f.model_dump() for f in findings]

    reasoning_note = f"IaC scan: {len(findings)} misconfigurations found"

    # LLM enhancement: find logic-level IaC flaws
    try:
        from .prompts import (
            SYSTEM_IAC_ANALYSIS,
            IaCAnalysisOutput,
        )

        context = json.dumps(
            {
                "finding_count": len(findings),
                "findings_sample": finding_dicts[:15],
                "target_types": list({f.target_type.value for f in findings}),
            },
            default=str,
        )
        llm_result = cast(
            IaCAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_IAC_ANALYSIS,
                user_prompt=(f"IaC scan results:\n{context}"),
                schema=IaCAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="code_security_scanner",
            node="scan_iac",
        )
        reasoning_note = f"{llm_result.summary} Logic flaws: {len(llm_result.logic_flaws)}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="code_security_scanner",
            node="scan_iac",
        )

    return {
        "iac_findings": finding_dicts,
        "stage": ScanStage.SCAN_IAC.value,
        "current_step": "scan_iac",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def scan_dependencies(
    state: dict[str, Any],
    toolkit: CodeSecurityScannerToolkit,
) -> dict[str, Any]:
    """Scan dependencies for known CVEs."""
    logger.info("code_security_scanner.node.scan_deps")
    state = _to_dict(state)
    targets = state.get("scan_targets", [])

    from .models import Repository

    raw_repos = state.get("repos_scanned", [])
    repos = [Repository(**r) if isinstance(r, dict) else r for r in raw_repos]

    findings = await toolkit.scan_dependencies(repos, targets)
    finding_dicts = [f.model_dump() for f in findings]

    reasoning_note = f"Dependency scan: {len(findings)} CVEs found"

    # LLM enhancement: assess exploitability
    try:
        from .prompts import (
            SYSTEM_DEPENDENCY_ANALYSIS,
            DependencyAnalysisOutput,
        )

        context = json.dumps(
            {
                "finding_count": len(findings),
                "findings": finding_dicts[:15],
                "ecosystems": list({f.ecosystem for f in findings}),
            },
            default=str,
        )
        llm_result = cast(
            DependencyAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_DEPENDENCY_ANALYSIS,
                user_prompt=(f"Dependency scan results:\n{context}"),
                schema=DependencyAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="code_security_scanner",
            node="scan_dependencies",
        )
        fp_ids = set(llm_result.false_positive_ids)
        if fp_ids:
            finding_dicts = [f for f in finding_dicts if f.get("cve_id", "") not in fp_ids]
        reasoning_note = f"{llm_result.summary} Exploitable: {llm_result.exploitable_count}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="code_security_scanner",
            node="scan_dependencies",
        )

    return {
        "dependency_findings": finding_dicts,
        "stage": ScanStage.SCAN_DEPENDENCIES.value,
        "current_step": "scan_dependencies",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def scan_application_code(
    state: dict[str, Any],
    toolkit: CodeSecurityScannerToolkit,
) -> dict[str, Any]:
    """Scan application code for SAST + AI-specific vulns."""
    logger.info("code_security_scanner.node.scan_code")
    state = _to_dict(state)
    targets = state.get("scan_targets", [])

    from .models import Repository

    raw_repos = state.get("repos_scanned", [])
    repos = [Repository(**r) if isinstance(r, dict) else r for r in raw_repos]

    findings = await toolkit.scan_application_code(repos, targets)
    finding_dicts = [f.model_dump() for f in findings]

    ai_count = sum(1 for f in findings if f.is_ai_specific)
    reasoning_note = f"Code scan: {len(findings)} issues ({ai_count} AI-specific)"

    # LLM enhancement: find logic-level code vulns
    try:
        from .prompts import (
            SYSTEM_CODE_ANALYSIS,
            CodeAnalysisOutput,
        )

        context = json.dumps(
            {
                "finding_count": len(findings),
                "findings_sample": finding_dicts[:15],
                "ai_specific_count": ai_count,
                "categories": list({f.category for f in findings}),
            },
            default=str,
        )
        llm_result = cast(
            CodeAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_CODE_ANALYSIS,
                user_prompt=(f"Code scan results:\n{context}"),
                schema=CodeAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="code_security_scanner",
            node="scan_application_code",
        )
        fp_ids = set(llm_result.false_positive_ids)
        if fp_ids:
            finding_dicts = [f for f in finding_dicts if f.get("id", "") not in fp_ids]
        reasoning_note = f"{llm_result.summary} AI risks: {len(llm_result.ai_specific_risks)}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="code_security_scanner",
            node="scan_application_code",
        )

    return {
        "code_findings": finding_dicts,
        "stage": ScanStage.SCAN_APPLICATION_CODE.value,
        "current_step": "scan_application_code",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def prioritize_findings(
    state: dict[str, Any],
    toolkit: CodeSecurityScannerToolkit,
) -> dict[str, Any]:
    """Prioritize all findings by risk with LLM reasoning."""
    logger.info("code_security_scanner.node.prioritize")
    state = _to_dict(state)

    raw_iac = state.get("iac_findings", [])
    raw_deps = state.get("dependency_findings", [])
    raw_code = state.get("code_findings", [])

    iac = [IaCScanResult(**f) if isinstance(f, dict) else f for f in raw_iac]
    deps = [DependencyScanResult(**f) if isinstance(f, dict) else f for f in raw_deps]
    code = [CodeScanResult(**f) if isinstance(f, dict) else f for f in raw_code]

    prioritized = toolkit.prioritize_findings(iac, deps, code)
    prioritized_dicts = [p.model_dump() for p in prioritized]

    total = len(prioritized)
    critical = sum(1 for p in prioritized if p.severity == "critical")
    reasoning_note = f"Prioritized {total} findings: {critical} critical"

    # LLM enhancement: deeper prioritization
    try:
        from .prompts import (
            SYSTEM_PRIORITIZATION,
            PrioritizationOutput,
        )

        context = json.dumps(
            {
                "total_findings": total,
                "critical_count": critical,
                "top_findings": prioritized_dicts[:20],
                "ai_specific": [p for p in prioritized_dicts if p.get("is_ai_specific")][:10],
            },
            default=str,
        )
        llm_result = cast(
            PrioritizationOutput,
            await llm_structured(
                system_prompt=SYSTEM_PRIORITIZATION,
                user_prompt=(f"Prioritization data:\n{context}"),
                schema=PrioritizationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="code_security_scanner",
            node="prioritize_findings",
        )
        # Apply LLM priority scores
        score_map = llm_result.priority_scores
        for p in prioritized_dicts:
            sid = p.get("source_finding_id", "")
            if sid in score_map:
                p["priority_score"] = score_map[sid]
        exploitable = set(llm_result.exploitable_ids)
        for p in prioritized_dicts:
            sid = p.get("source_finding_id", "")
            if sid in exploitable:
                p["is_exploitable"] = True
        reasoning_note = f"{llm_result.summary} {llm_result.risk_narrative[:80]}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="code_security_scanner",
            node="prioritize_findings",
        )

    return {
        "prioritized": prioritized_dicts,
        "total_findings": total,
        "critical_count": critical,
        "stage": ScanStage.PRIORITIZE_FINDINGS.value,
        "current_step": "prioritize_findings",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: CodeSecurityScannerToolkit,
) -> dict[str, Any]:
    """Generate final scan report with statistics."""
    logger.info("code_security_scanner.node.report")
    state = _to_dict(state)

    iac = state.get("iac_findings", [])
    deps = state.get("dependency_findings", [])
    code = state.get("code_findings", [])
    prioritized = state.get("prioritized", [])
    session_start = state.get("session_start", time.time())

    # Severity distribution
    sev_dist: dict[str, int] = {}
    for p in prioritized:
        sev = p.get("severity", "medium")
        sev_dist[sev] = sev_dist.get(sev, 0) + 1

    # Finding type distribution
    type_dist = {
        "iac": len(iac),
        "dependency": len(deps),
        "code": len(code),
    }

    ai_count = sum(1 for p in prioritized if p.get("is_ai_specific", False))
    exploitable = sum(1 for p in prioritized if p.get("is_exploitable", False))

    duration_ms = (time.time() - session_start) * 1000

    stats = {
        "total_findings": len(prioritized),
        "critical_count": sev_dist.get("critical", 0),
        "high_count": sev_dist.get("high", 0),
        "medium_count": sev_dist.get("medium", 0),
        "low_count": sev_dist.get("low", 0),
        "ai_specific_count": ai_count,
        "exploitable_count": exploitable,
        "severity_distribution": sev_dist,
        "finding_type_distribution": type_dist,
        "scan_duration_ms": round(duration_ms, 2),
    }

    return {
        "stats": stats,
        "total_findings": len(prioritized),
        "critical_count": sev_dist.get("critical", 0),
        "stage": ScanStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report: {len(prioritized)} findings, "
            f"{sev_dist.get('critical', 0)} critical, "
            f"{ai_count} AI-specific, "
            f"{exploitable} exploitable"
        ],
    }
