"""Cloud Network Firewall Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CNFStage,
    FirewallRule,
    OverpermissiveRule,
    RuleSeverity,
    ShadowRule,
)
from .tools import CloudNetworkFirewallToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: CloudNetworkFirewallToolkit | None = None


def set_toolkit(
    toolkit: CloudNetworkFirewallToolkit,
) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> CloudNetworkFirewallToolkit:
    """Get the module-level toolkit, creating default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = CloudNetworkFirewallToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: collect_rules
# ------------------------------------------------------------------
async def collect_rules(
    state: dict[str, Any],
    toolkit: CloudNetworkFirewallToolkit,
) -> dict[str, Any]:
    """Collect firewall rules from cloud platforms."""
    logger.info("cnf.node.collect_rules")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    platforms = state.get("platforms", ["aws_sg"])

    rules = await toolkit.collect_firewall_rules(tenant_id, platforms)
    rules_data = [r.model_dump() for r in rules]

    return {
        "stage": CNFStage.ANALYZE_COVERAGE.value,
        "firewall_rules": rules_data,
        "current_step": "collect_rules",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(rules)} firewall rules across {', '.join(platforms)}"],
    }


# ------------------------------------------------------------------
# Node 2: analyze_coverage
# ------------------------------------------------------------------
async def analyze_coverage(
    state: dict[str, Any],
    toolkit: CloudNetworkFirewallToolkit,
) -> dict[str, Any]:
    """Analyze firewall rule coverage per group."""
    logger.info("cnf.node.analyze_coverage")
    state = _to_dict(state)

    raw_rules = state.get("firewall_rules", [])
    rules = [FirewallRule(**r) for r in raw_rules]

    coverage = await toolkit.analyze_coverage(rules)
    coverage_data = [c.model_dump() for c in coverage]

    avg_score = (
        round(
            sum(c.coverage_score for c in coverage) / len(coverage),
            1,
        )
        if coverage
        else 0.0
    )
    total_unused = sum(c.unused_rules for c in coverage)

    reasoning_note = (
        f"Analyzed {len(coverage)} groups, avg coverage {avg_score}%, {total_unused} unused rules"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_COVERAGE_ANALYSIS,
            CoverageOutput,
        )

        context = json.dumps(
            {
                "groups": len(coverage),
                "avg_coverage": avg_score,
                "unused_rules": total_unused,
                "details": [
                    {
                        "group_id": c.group_id,
                        "total": c.total_rules,
                        "ingress": c.ingress_rules,
                        "egress": c.egress_rules,
                        "unused": c.unused_rules,
                        "score": c.coverage_score,
                    }
                    for c in coverage[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            CoverageOutput,
            await llm_structured(
                system_prompt=SYSTEM_COVERAGE_ANALYSIS,
                user_prompt=(f"Coverage context:\n{context}"),
                schema=CoverageOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cnf",
            node="analyze_coverage",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cnf",
            node="analyze_coverage",
        )

    return {
        "stage": CNFStage.DETECT_OVERPERMISSIVE.value,
        "coverage_results": coverage_data,
        "current_step": "analyze_coverage",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Node 3: detect_overpermissive
# ------------------------------------------------------------------
async def detect_overpermissive(
    state: dict[str, Any],
    toolkit: CloudNetworkFirewallToolkit,
) -> dict[str, Any]:
    """Detect overly permissive firewall rules."""
    logger.info("cnf.node.detect_overpermissive")
    state = _to_dict(state)

    raw_rules = state.get("firewall_rules", [])
    rules = [FirewallRule(**r) for r in raw_rules]

    findings = await toolkit.detect_overpermissive(rules)
    findings_data = [f.model_dump() for f in findings]

    critical = sum(1 for f in findings if f.severity == RuleSeverity.CRITICAL)
    high = sum(1 for f in findings if f.severity == RuleSeverity.HIGH)

    reasoning_note = (
        f"Detected {len(findings)} overpermissive rules: {critical} critical, {high} high"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_OVERPERMISSIVE_DETECTION,
            OverpermissiveOutput,
        )

        context = json.dumps(
            {
                "total": len(findings),
                "critical": critical,
                "high": high,
                "top_findings": [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity.value,
                        "reason": f.reason,
                        "risk": f.risk_score,
                    }
                    for f in sorted(
                        findings,
                        key=lambda x: x.risk_score,
                        reverse=True,
                    )[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            OverpermissiveOutput,
            await llm_structured(
                system_prompt=SYSTEM_OVERPERMISSIVE_DETECTION,
                user_prompt=(f"Overpermissive context:\n{context}"),
                schema=OverpermissiveOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cnf",
            node="detect_overpermissive",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cnf",
            node="detect_overpermissive",
        )

    return {
        "stage": CNFStage.FIND_SHADOW_RULES.value,
        "overpermissive_rules": findings_data,
        "current_step": "detect_overpermissive",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Node 4: find_shadow_rules
# ------------------------------------------------------------------
async def find_shadow_rules(
    state: dict[str, Any],
    toolkit: CloudNetworkFirewallToolkit,
) -> dict[str, Any]:
    """Find shadow rules masked by higher-priority rules."""
    logger.info("cnf.node.find_shadow_rules")
    state = _to_dict(state)

    raw_rules = state.get("firewall_rules", [])
    rules = [FirewallRule(**r) for r in raw_rules]

    shadows = await toolkit.find_shadow_rules(rules)
    shadows_data = [s.model_dump() for s in shadows]

    removable = sum(1 for s in shadows if s.removable)

    reasoning_note = f"Found {len(shadows)} shadow rules, {removable} safely removable"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_SHADOW_RULE_DETECTION,
            ShadowRuleOutput,
        )

        context = json.dumps(
            {
                "total_shadows": len(shadows),
                "removable": removable,
                "details": [
                    {
                        "shadowed": s.shadowed_rule_id,
                        "by": s.shadowing_rule_id,
                        "impact": s.impact,
                        "removable": s.removable,
                    }
                    for s in shadows[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ShadowRuleOutput,
            await llm_structured(
                system_prompt=SYSTEM_SHADOW_RULE_DETECTION,
                user_prompt=(f"Shadow rule context:\n{context}"),
                schema=ShadowRuleOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cnf",
            node="find_shadow_rules",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cnf",
            node="find_shadow_rules",
        )

    return {
        "stage": CNFStage.OPTIMIZE_RULES.value,
        "shadow_rules": shadows_data,
        "current_step": "find_shadow_rules",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Node 5: optimize_rules
# ------------------------------------------------------------------
async def optimize_rules(
    state: dict[str, Any],
    toolkit: CloudNetworkFirewallToolkit,
) -> dict[str, Any]:
    """Generate rule optimization recommendations."""
    logger.info("cnf.node.optimize_rules")
    state = _to_dict(state)

    raw_rules = state.get("firewall_rules", [])
    rules = [FirewallRule(**r) for r in raw_rules]
    raw_op = state.get("overpermissive_rules", [])
    overpermissive = [OverpermissiveRule(**o) for o in raw_op]
    raw_sh = state.get("shadow_rules", [])
    shadows = [ShadowRule(**s) for s in raw_sh]

    opts = await toolkit.optimize_rules(rules, overpermissive, shadows)
    opts_data = [o.model_dump() for o in opts]

    auto_count = sum(1 for o in opts if o.auto_applicable)

    reasoning_note = f"Generated {len(opts)} optimizations, {auto_count} auto-applicable"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_RULE_OPTIMIZATION,
            OptimizationOutput,
        )

        context = json.dumps(
            {
                "total_optimizations": len(opts),
                "auto_applicable": auto_count,
                "types": {
                    ot: sum(1 for o in opts if o.optimization_type == ot)
                    for ot in {o.optimization_type for o in opts}
                },
                "total_risk_reduction": round(sum(o.risk_reduction for o in opts), 1),
            },
            default=str,
        )
        llm_result = cast(
            OptimizationOutput,
            await llm_structured(
                system_prompt=SYSTEM_RULE_OPTIMIZATION,
                user_prompt=(f"Optimization context:\n{context}"),
                schema=OptimizationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cnf",
            node="optimize_rules",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cnf",
            node="optimize_rules",
        )

    return {
        "stage": CNFStage.REPORT.value,
        "optimizations": opts_data,
        "current_step": "optimize_rules",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Node 6: generate_report
# ------------------------------------------------------------------
async def generate_report(
    state: dict[str, Any],
    toolkit: CloudNetworkFirewallToolkit,
) -> dict[str, Any]:
    """Generate the final firewall posture report."""
    logger.info("cnf.node.generate_report")
    state = _to_dict(state)

    raw_rules = state.get("firewall_rules", [])
    raw_coverage = state.get("coverage_results", [])
    raw_op = state.get("overpermissive_rules", [])
    raw_sh = state.get("shadow_rules", [])
    raw_opts = state.get("optimizations", [])

    # Compute security score
    total_rules = len(raw_rules)
    op_count = len(raw_op)
    sh_count = len(raw_sh)
    penalty = (op_count * 5) + (sh_count * 2)
    security_score = round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    severity_dist: dict[str, int] = {}
    for o in raw_op:
        sev = o.get("severity", "medium")
        severity_dist[sev] = severity_dist.get(sev, 0) + 1

    auto_opts = sum(1 for o in raw_opts if o.get("auto_applicable", False))

    elapsed = round(
        (time.time() - state.get("session_start", time.time())) * 1000,
        1,
    )

    stats = {
        "rules_collected": total_rules,
        "groups_analyzed": len(raw_coverage),
        "overpermissive_found": op_count,
        "shadow_rules_found": sh_count,
        "optimizations_generated": len(raw_opts),
        "auto_applicable": auto_opts,
        "severity_distribution": severity_dist,
        "security_score": security_score,
        "platforms": state.get("platforms", []),
    }

    report_summary = (
        f"Firewall security score: {security_score}/100. "
        f"{total_rules} rules, {op_count} overpermissive, "
        f"{sh_count} shadow, {len(raw_opts)} optimizations."
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_FIREWALL_REPORT,
            FirewallReportOutput,
        )

        context = json.dumps(stats, default=str)
        llm_result = cast(
            FirewallReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_FIREWALL_REPORT,
                user_prompt=f"Firewall stats:\n{context}",
                schema=FirewallReportOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cnf",
            node="generate_report",
        )
        report_summary = llm_result.summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cnf",
            node="generate_report",
        )

    return {
        "stage": CNFStage.REPORT.value,
        "stats": stats,
        "security_score": security_score,
        "session_duration_ms": elapsed,
        "current_step": "generate_report",
        "reasoning_chain": state.get("reasoning_chain", []) + [report_summary],
    }
