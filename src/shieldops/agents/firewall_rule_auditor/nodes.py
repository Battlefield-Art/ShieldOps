"""Firewall Rule Auditor Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AuditStage,
    FirewallRule,
    RuleRisk,
    RuleViolation,
)
from .tools import FirewallAuditToolkit

logger = structlog.get_logger()

_toolkit: FirewallAuditToolkit | None = None


def set_toolkit(toolkit: FirewallAuditToolkit) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> FirewallAuditToolkit:
    global _toolkit
    if _toolkit is None:
        _toolkit = FirewallAuditToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: collect_rules
# ------------------------------------------------------------------
async def collect_rules(
    state: dict[str, Any],
    toolkit: FirewallAuditToolkit,
) -> dict[str, Any]:
    """Enumerate firewall rules across requested providers."""
    logger.info("firewall_audit.node.collect_rules")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    providers = state.get("providers", ["aws_sg"])

    rules = await toolkit.collect_rules(tenant_id, providers)
    rules_data = [r.model_dump() for r in rules]

    return {
        "stage": AuditStage.DETECT_VIOLATIONS.value,
        "firewall_rules": rules_data,
        "current_step": "collect_rules",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(rules)} firewall rules across {', '.join(providers)}"],
    }


# ------------------------------------------------------------------
# Node 2: detect_violations
# ------------------------------------------------------------------
async def detect_violations(
    state: dict[str, Any],
    toolkit: FirewallAuditToolkit,
) -> dict[str, Any]:
    """Detect misconfigurations and violations in collected rules."""
    logger.info("firewall_audit.node.detect_violations")
    state = _to_dict(state)

    raw_rules = state.get("firewall_rules", [])
    rules = [FirewallRule(**r) for r in raw_rules]

    violations = await toolkit.detect_violations(rules)
    violations_data = [v.model_dump() for v in violations]

    critical = sum(1 for v in violations if v.risk == RuleRisk.CRITICAL)
    high = sum(1 for v in violations if v.risk == RuleRisk.HIGH)

    reasoning_note = f"Detected {len(violations)} violations: {critical} critical, {high} high"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_VIOLATION_ANALYSIS,
            ViolationAnalysisOutput,
        )

        context = json.dumps(
            {
                "total_violations": len(violations),
                "critical": critical,
                "high": high,
                "types": list({v.violation_type for v in violations}),
                "top_violations": [
                    {
                        "type": v.violation_type,
                        "risk": v.risk.value if hasattr(v.risk, "value") else str(v.risk),
                        "rule_id": v.rule_id,
                    }
                    for v in violations[:15]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ViolationAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_VIOLATION_ANALYSIS,
                user_prompt=f"Violation context:\n{context}",
                schema=ViolationAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="firewall_audit",
            node="detect_violations",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="firewall_audit",
            node="detect_violations",
        )

    return {
        "stage": AuditStage.CLASSIFY_RISKS.value,
        "violations": violations_data,
        "current_step": "detect_violations",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Node 3: classify_risks
# ------------------------------------------------------------------
async def classify_risks(
    state: dict[str, Any],
    toolkit: FirewallAuditToolkit,
) -> dict[str, Any]:
    """Prioritize violations by risk level."""
    logger.info("firewall_audit.node.classify_risks")
    state = _to_dict(state)

    raw_violations = state.get("violations", [])
    violations = [RuleViolation(**v) for v in raw_violations]

    risk_weight = {
        RuleRisk.CRITICAL: 5,
        RuleRisk.HIGH: 4,
        RuleRisk.MEDIUM: 3,
        RuleRisk.LOW: 2,
        RuleRisk.INFO: 1,
    }
    prioritized = sorted(
        violations,
        key=lambda v: risk_weight.get(v.risk, 0),
        reverse=True,
    )
    prioritized_data = [v.model_dump() for v in prioritized]

    return {
        "stage": AuditStage.CHECK_COMPLIANCE.value,
        "violations": prioritized_data,
        "current_step": "classify_risks",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Classified {len(prioritized)} violations by risk priority"],
    }


# ------------------------------------------------------------------
# Node 4: check_compliance
# ------------------------------------------------------------------
async def check_compliance(
    state: dict[str, Any],
    toolkit: FirewallAuditToolkit,
) -> dict[str, Any]:
    """Map violations to compliance frameworks."""
    logger.info("firewall_audit.node.check_compliance")
    state = _to_dict(state)

    raw_violations = state.get("violations", [])
    violations = [RuleViolation(**v) for v in raw_violations]

    compliance_results = await toolkit.check_compliance(violations)

    failing = [r for r in compliance_results if r.get("status") == "fail"]

    reasoning_note = (
        f"Compliance check: {len(failing)} frameworks failing out of {len(compliance_results)}"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_COMPLIANCE_CHECK,
            ComplianceCheckOutput,
        )

        context = json.dumps(
            {
                "total_frameworks": len(compliance_results),
                "failing": len(failing),
                "results": compliance_results,
            },
            default=str,
        )
        llm_result = cast(
            ComplianceCheckOutput,
            await llm_structured(
                system_prompt=SYSTEM_COMPLIANCE_CHECK,
                user_prompt=f"Compliance context:\n{context}",
                schema=ComplianceCheckOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="firewall_audit",
            node="check_compliance",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="firewall_audit",
            node="check_compliance",
        )

    return {
        "stage": AuditStage.RECOMMEND_FIXES.value,
        "compliance_results": compliance_results,
        "current_step": "check_compliance",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Node 5: recommend_fixes
# ------------------------------------------------------------------
async def recommend_fixes(
    state: dict[str, Any],
    toolkit: FirewallAuditToolkit,
) -> dict[str, Any]:
    """Generate fix recommendations for detected violations."""
    logger.info("firewall_audit.node.recommend_fixes")
    state = _to_dict(state)

    raw_violations = state.get("violations", [])
    violations = [RuleViolation(**v) for v in raw_violations]

    findings = await toolkit.recommend_fixes(violations)
    findings_data = [f.model_dump() for f in findings]

    reasoning_note = (
        f"Generated {len(findings)} fix recommendations "
        f"covering {sum(f.affected_rules for f in findings)} rules"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_FIX_RECOMMENDATION,
            FixRecommendationOutput,
        )

        context = json.dumps(
            {
                "total_findings": len(findings),
                "auto_fixable": sum(1 for v in violations if v.auto_fixable),
                "manual_required": sum(1 for v in violations if not v.auto_fixable),
                "findings": [
                    {
                        "title": f.title,
                        "risk": f.risk.value if hasattr(f.risk, "value") else str(f.risk),
                        "affected_rules": f.affected_rules,
                    }
                    for f in findings
                ],
            },
            default=str,
        )
        llm_result = cast(
            FixRecommendationOutput,
            await llm_structured(
                system_prompt=SYSTEM_FIX_RECOMMENDATION,
                user_prompt=f"Fix recommendation context:\n{context}",
                schema=FixRecommendationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="firewall_audit",
            node="recommend_fixes",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="firewall_audit",
            node="recommend_fixes",
        )

    return {
        "stage": AuditStage.REPORT.value,
        "findings": findings_data,
        "current_step": "recommend_fixes",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Node 6: generate_report
# ------------------------------------------------------------------
async def generate_report(
    state: dict[str, Any],
    toolkit: FirewallAuditToolkit,
) -> dict[str, Any]:
    """Generate the final firewall audit report."""
    logger.info("firewall_audit.node.generate_report")
    state = _to_dict(state)

    raw_rules = state.get("firewall_rules", [])
    raw_violations = state.get("violations", [])
    raw_findings = state.get("findings", [])
    compliance_results = state.get("compliance_results", [])

    # Compute audit score
    total_rules = len(raw_rules) if raw_rules else 1
    violated_rule_ids = {v.get("rule_id") for v in raw_violations}
    clean_count = total_rules - len(violated_rule_ids)
    audit_score = round((clean_count / total_rules) * 100.0, 1)

    # Severity distribution
    risk_dist: dict[str, int] = {}
    for v in raw_violations:
        risk = v.get("risk", "medium")
        risk_dist[risk] = risk_dist.get(risk, 0) + 1

    elapsed = round(
        (time.time() - state.get("session_start", time.time())) * 1000,
        1,
    )

    stats = {
        "rules_audited": total_rules,
        "violations_found": len(raw_violations),
        "risk_distribution": risk_dist,
        "compliance_frameworks_checked": len(compliance_results),
        "findings_generated": len(raw_findings),
        "auto_fixable": sum(1 for v in raw_violations if v.get("auto_fixable", False)),
        "audit_score": audit_score,
        "providers": state.get("providers", []),
    }

    report_summary = (
        f"Firewall audit score: {audit_score}/100. "
        f"{total_rules} rules, {len(raw_violations)} violations, "
        f"{len(raw_findings)} findings."
    )

    # LLM enhancement
    try:
        from .prompts import SYSTEM_AUDIT_REPORT, AuditReportOutput

        context = json.dumps(stats, default=str)
        llm_result = cast(
            AuditReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_AUDIT_REPORT,
                user_prompt=f"Audit stats:\n{context}",
                schema=AuditReportOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="firewall_audit",
            node="generate_report",
        )
        report_summary = llm_result.summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="firewall_audit",
            node="generate_report",
        )

    return {
        "stage": AuditStage.REPORT.value,
        "stats": stats,
        "audit_score": audit_score,
        "session_duration_ms": elapsed,
        "current_step": "generate_report",
        "reasoning_chain": state.get("reasoning_chain", []) + [report_summary],
    }
