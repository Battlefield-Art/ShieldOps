"""Automated Security Testing Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    SecurityFinding,
    TestCategory,
    TestScope,
    TestStage,
)
from .tools import SecurityTestingToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def define_scope(state: dict[str, Any], toolkit: SecurityTestingToolkit) -> dict[str, Any]:
    """Define the security testing scope — targets, categories, exclusions."""
    logger.info("security_testing.node.define_scope")
    state = _to_dict(state)

    # Extract scope parameters from state or use defaults
    targets = state.get("targets", ["10.0.0.0/24", "app-server-01", "db-server-01"])
    raw_categories = state.get("categories", [c.value for c in TestCategory])
    exclusions = state.get("exclusions", [])

    categories = [TestCategory(c) for c in raw_categories]

    scope = await toolkit.define_scope(
        targets=targets,
        categories=categories,
        exclusions=exclusions,
    )

    return {
        "stage": TestStage.SCAN.value,
        "scope": scope.model_dump(),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Defined scope: {len(targets)} targets, "
            f"{len(categories)} categories, {len(exclusions)} exclusions"
        ],
    }


async def execute_scans(state: dict[str, Any], toolkit: SecurityTestingToolkit) -> dict[str, Any]:
    """Execute security scans across all targets and categories."""
    logger.info("security_testing.node.execute_scans")
    state = _to_dict(state)

    raw_scope = state.get("scope", {})
    scope = TestScope(**raw_scope)

    all_findings: list[dict[str, Any]] = []

    for target in scope.targets:
        # Skip excluded targets
        if target in scope.exclusions:
            continue

        for category in scope.categories:
            if category == TestCategory.VULNERABILITY:
                findings = await toolkit.run_vulnerability_scan(target)
            elif category in (TestCategory.CONFIGURATION, TestCategory.COMPLIANCE):
                findings = await toolkit.run_config_audit(target)
            elif category == TestCategory.CREDENTIAL:
                findings = await toolkit.run_credential_check(target)
            elif category == TestCategory.NETWORK:
                # Network scans use vulnerability scanner with network focus
                findings = await toolkit.run_vulnerability_scan(target)
                for f in findings:
                    f.category = TestCategory.NETWORK
            else:
                findings = []

            all_findings.extend([f.model_dump() for f in findings])

    return {
        "stage": TestStage.ANALYZE.value,
        "findings": all_findings,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Executed scans: found {len(all_findings)} raw findings"],
    }


async def analyze_findings(
    state: dict[str, Any], toolkit: SecurityTestingToolkit
) -> dict[str, Any]:
    """Analyze and deduplicate findings, apply RBA risk scoring."""
    logger.info("security_testing.node.analyze_findings")
    state = _to_dict(state)

    raw_findings = state.get("findings", [])
    findings = [SecurityFinding(**f) for f in raw_findings]

    # Deduplicate by title + affected_resource
    seen: set[str] = set()
    deduped: list[SecurityFinding] = []
    for f in findings:
        key = f"{f.title}:{f.affected_resource}"
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Apply RBA risk score adjustments based on severity
    severity_multiplier = {
        "critical": 1.5,
        "high": 1.2,
        "medium": 1.0,
        "low": 0.7,
        "info": 0.3,
    }
    for f in deduped:
        multiplier = severity_multiplier.get(f.severity.value, 1.0)
        f.risk_score = min(int(f.risk_score * multiplier), 100)

    # Generate recommendations from top findings
    recommendations: list[str] = []
    sorted_findings = sorted(deduped, key=lambda f: f.risk_score, reverse=True)
    for f in sorted_findings[:5]:
        recommendations.append(f"[{f.severity.value.upper()}] {f.title}: {f.remediation}")

    reasoning_note = (
        f"Analyzed {len(raw_findings)} findings, "
        f"deduplicated to {len(deduped)}, "
        f"generated {len(recommendations)} recommendations"
    )

    # LLM enhancement: deeper findings analysis
    try:
        from .prompts import SYSTEM_ANALYZE_FINDINGS, FindingsAnalysisResult

        findings_context = json.dumps(
            {
                "total_raw": len(raw_findings),
                "deduped": len(deduped),
                "findings_summary": [
                    {
                        "title": f.title,
                        "severity": f.severity.value,
                        "risk_score": f.risk_score,
                        "category": f.category.value,
                    }
                    for f in sorted_findings[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            FindingsAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE_FINDINGS,
                user_prompt=f"Security findings context:\n{findings_context}",
                schema=FindingsAnalysisResult,
            ),
        )
        logger.info("llm_enhanced", agent="security_testing", node="analyze_findings")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="security_testing", node="analyze_findings")

    return {
        "stage": TestStage.REPORT.value,
        "findings": [f.model_dump() for f in sorted_findings],
        "recommendations": recommendations,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(state: dict[str, Any], toolkit: SecurityTestingToolkit) -> dict[str, Any]:
    """Generate the final security testing report."""
    logger.info("security_testing.node.generate_report")
    state = _to_dict(state)

    raw_findings = state.get("findings", [])
    findings = [SecurityFinding(**f) for f in raw_findings]

    raw_scope = state.get("scope", {})
    scope = TestScope(**raw_scope)

    report = await toolkit.generate_report(findings=findings, scope=scope)

    return {
        "stage": TestStage.REPORT.value,
        "report": report.model_dump(),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Generated report: {report.critical_count} critical, "
            f"{report.high_count} high, "
            f"total risk score {report.risk_score_total}, "
            f"pass rate {report.pass_rate:.1%}"
        ],
    }
