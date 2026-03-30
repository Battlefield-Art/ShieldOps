"""IAM Policy Analyzer Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    IAMPolicy,
    IPAStage,
    OverprivilegeAlert,
    PermissionAnalysis,
    RiskLevel,
)
from .tools import IAMPolicyAnalyzerToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: IAMPolicyAnalyzerToolkit | None = None


def set_toolkit(
    toolkit: IAMPolicyAnalyzerToolkit,
) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> IAMPolicyAnalyzerToolkit:
    """Get the module-level toolkit, creating default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = IAMPolicyAnalyzerToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict if Pydantic model."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ---------------------------------------------------------------
# Node 1: collect_policies
# ---------------------------------------------------------------
async def collect_policies(
    state: dict[str, Any],
    toolkit: IAMPolicyAnalyzerToolkit,
) -> dict[str, Any]:
    """Collect IAM policies across cloud providers."""
    logger.info("iam_policy_analyzer.node.collect_policies")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    providers = state.get("providers", ["aws"])

    policies = await toolkit.collect_policies(tenant_id, providers)
    policies_data = [p.model_dump() for p in policies]

    return {
        "stage": IPAStage.ANALYZE_PERMISSIONS.value,
        "policies": policies_data,
        "current_step": "collect_policies",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(policies)} IAM policies across {', '.join(providers)}"],
    }


# ---------------------------------------------------------------
# Node 2: analyze_permissions
# ---------------------------------------------------------------
async def analyze_permissions(
    state: dict[str, Any],
    toolkit: IAMPolicyAnalyzerToolkit,
) -> dict[str, Any]:
    """Analyze each policy for risk indicators."""
    logger.info(
        "iam_policy_analyzer.node.analyze_permissions",
    )
    state = _to_dict(state)

    raw_policies = state.get("policies", [])
    policies = [IAMPolicy(**p) for p in raw_policies]

    analyses = await toolkit.analyze_permissions(policies)
    analyses_data = [a.model_dump() for a in analyses]

    high_risk = sum(1 for a in analyses if a.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH))

    reasoning_note = f"Analyzed {len(analyses)} policies: {high_risk} high/critical risk"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_PERMISSION_ANALYSIS,
            PermissionAnalysisOutput,
        )

        context = json.dumps(
            {
                "total_policies": len(analyses),
                "high_risk": high_risk,
                "wildcard_total": sum(a.wildcard_actions for a in analyses),
                "admin_total": sum(a.admin_actions for a in analyses),
                "top_risks": [
                    {
                        "principal": a.principal_name,
                        "risk_score": a.risk_score,
                        "wildcards": a.wildcard_actions,
                        "scope": a.resource_scope,
                    }
                    for a in sorted(
                        analyses,
                        key=lambda x: x.risk_score,
                        reverse=True,
                    )[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PermissionAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_PERMISSION_ANALYSIS,
                user_prompt=(f"Permission analysis context:\n{context}"),
                schema=PermissionAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="iam_policy_analyzer",
            node="analyze_permissions",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="iam_policy_analyzer",
            node="analyze_permissions",
        )

    return {
        "stage": IPAStage.DETECT_OVERPRIVILEGE.value,
        "permission_analyses": analyses_data,
        "current_step": "analyze_permissions",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ---------------------------------------------------------------
# Node 3: detect_overprivilege
# ---------------------------------------------------------------
async def detect_overprivilege(
    state: dict[str, Any],
    toolkit: IAMPolicyAnalyzerToolkit,
) -> dict[str, Any]:
    """Flag over-privileged principals."""
    logger.info(
        "iam_policy_analyzer.node.detect_overprivilege",
    )
    state = _to_dict(state)

    raw_analyses = state.get("permission_analyses", [])
    analyses = [PermissionAnalysis(**a) for a in raw_analyses]
    raw_policies = state.get("policies", [])
    policies = [IAMPolicy(**p) for p in raw_policies]

    alerts = await toolkit.detect_overprivilege(analyses, policies)
    alerts_data = [a.model_dump() for a in alerts]

    critical = sum(1 for a in alerts if a.risk_level == RiskLevel.CRITICAL)
    high = sum(1 for a in alerts if a.risk_level == RiskLevel.HIGH)

    reasoning_note = (
        f"Detected {len(alerts)} over-privileged principals: {critical} critical, {high} high"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_OVERPRIVILEGE_DETECTION,
            OverprivilegeOutput,
        )

        context = json.dumps(
            {
                "total_alerts": len(alerts),
                "critical": critical,
                "high": high,
                "alerts": [
                    {
                        "principal": a.principal_name,
                        "type": a.overprivilege_type,
                        "blast_radius": a.blast_radius,
                        "risk_level": a.risk_level.value,
                    }
                    for a in alerts[:15]
                ],
            },
            default=str,
        )
        llm_result = cast(
            OverprivilegeOutput,
            await llm_structured(
                system_prompt=(SYSTEM_OVERPRIVILEGE_DETECTION),
                user_prompt=(f"Over-privilege context:\n{context}"),
                schema=OverprivilegeOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="iam_policy_analyzer",
            node="detect_overprivilege",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="iam_policy_analyzer",
            node="detect_overprivilege",
        )

    return {
        "stage": IPAStage.FIND_UNUSED.value,
        "overprivilege_alerts": alerts_data,
        "current_step": "detect_overprivilege",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ---------------------------------------------------------------
# Node 4: find_unused
# ---------------------------------------------------------------
async def find_unused(
    state: dict[str, Any],
    toolkit: IAMPolicyAnalyzerToolkit,
) -> dict[str, Any]:
    """Identify unused permissions across all principals."""
    logger.info("iam_policy_analyzer.node.find_unused")
    state = _to_dict(state)

    raw_policies = state.get("policies", [])
    policies = [IAMPolicy(**p) for p in raw_policies]

    unused = await toolkit.find_unused_permissions(policies)
    unused_data = [u.model_dump() for u in unused]

    high_risk_unused = sum(
        1 for u in unused if u.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    )

    reasoning_note = f"Found {len(unused)} unused permissions, {high_risk_unused} high-risk"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_UNUSED_PERMISSIONS,
            UnusedPermissionsOutput,
        )

        # Group by principal
        by_principal: dict[str, int] = {}
        for u in unused:
            by_principal[u.principal_name] = by_principal.get(u.principal_name, 0) + 1

        context = json.dumps(
            {
                "total_unused": len(unused),
                "high_risk": high_risk_unused,
                "by_principal": dict(
                    sorted(
                        by_principal.items(),
                        key=lambda x: x[1],
                        reverse=True,
                    )[:10]
                ),
            },
            default=str,
        )
        llm_result = cast(
            UnusedPermissionsOutput,
            await llm_structured(
                system_prompt=SYSTEM_UNUSED_PERMISSIONS,
                user_prompt=(f"Unused permissions context:\n{context}"),
                schema=UnusedPermissionsOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="iam_policy_analyzer",
            node="find_unused",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="iam_policy_analyzer",
            node="find_unused",
        )

    return {
        "stage": IPAStage.RECOMMEND_FIXES.value,
        "unused_permissions": unused_data,
        "current_step": "find_unused",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ---------------------------------------------------------------
# Node 5: recommend_fixes
# ---------------------------------------------------------------
async def recommend_fixes(
    state: dict[str, Any],
    toolkit: IAMPolicyAnalyzerToolkit,
) -> dict[str, Any]:
    """Generate policy-tightening recommendations."""
    logger.info(
        "iam_policy_analyzer.node.recommend_fixes",
    )
    state = _to_dict(state)

    raw_alerts = state.get("overprivilege_alerts", [])
    alerts = [OverprivilegeAlert(**a) for a in raw_alerts]
    raw_unused = state.get("unused_permissions", [])
    from .models import UnusedPermission

    unused = [UnusedPermission(**u) for u in raw_unused]
    raw_policies = state.get("policies", [])
    policies = [IAMPolicy(**p) for p in raw_policies]

    recs = await toolkit.generate_recommendations(alerts, unused, policies)
    recs_data = [r.model_dump() for r in recs]

    auto_count = sum(1 for r in recs if r.auto_applicable)

    reasoning_note = f"Generated {len(recs)} recommendations, {auto_count} auto-applicable"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_POLICY_RECOMMENDATIONS,
            PolicyRecommendationOutput,
        )

        context = json.dumps(
            {
                "total_recs": len(recs),
                "auto_applicable": auto_count,
                "by_type": {
                    "replace": sum(1 for r in recs if r.recommendation_type == "replace"),
                    "scope-down": sum(1 for r in recs if r.recommendation_type == "scope-down"),
                    "remove": sum(1 for r in recs if r.recommendation_type == "remove"),
                },
                "total_risk_reduction": round(
                    sum(r.risk_reduction for r in recs),
                    1,
                ),
            },
            default=str,
        )
        llm_result = cast(
            PolicyRecommendationOutput,
            await llm_structured(
                system_prompt=(SYSTEM_POLICY_RECOMMENDATIONS),
                user_prompt=(f"Recommendation context:\n{context}"),
                schema=PolicyRecommendationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="iam_policy_analyzer",
            node="recommend_fixes",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="iam_policy_analyzer",
            node="recommend_fixes",
        )

    return {
        "stage": IPAStage.REPORT.value,
        "recommendations": recs_data,
        "current_step": "recommend_fixes",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ---------------------------------------------------------------
# Node 6: generate_report
# ---------------------------------------------------------------
async def generate_report(
    state: dict[str, Any],
    toolkit: IAMPolicyAnalyzerToolkit,
) -> dict[str, Any]:
    """Generate final IAM posture report with stats."""
    logger.info(
        "iam_policy_analyzer.node.generate_report",
    )
    state = _to_dict(state)

    raw_policies = state.get("policies", [])
    raw_analyses = state.get("permission_analyses", [])
    raw_alerts = state.get("overprivilege_alerts", [])
    raw_unused = state.get("unused_permissions", [])
    raw_recs = state.get("recommendations", [])

    # Compute risk score
    if raw_analyses:
        scores = [a.get("risk_score", 0.0) for a in raw_analyses]
        avg_risk = round(sum(scores) / len(scores), 1)
    else:
        avg_risk = 0.0

    # Invert to get a posture score (100 = perfect)
    risk_score = round(100.0 - avg_risk, 1)

    # Severity distribution for alerts
    severity_dist: dict[str, int] = {}
    for a in raw_alerts:
        sev = a.get("risk_level", "medium")
        severity_dist[sev] = severity_dist.get(sev, 0) + 1

    auto_fixable = sum(1 for r in raw_recs if r.get("auto_applicable", False))

    elapsed = round(
        (time.time() - state.get("session_start", time.time())) * 1000,
        1,
    )

    stats = {
        "policies_analyzed": len(raw_policies),
        "permission_analyses": len(raw_analyses),
        "overprivilege_alerts": len(raw_alerts),
        "unused_permissions": len(raw_unused),
        "recommendations": len(raw_recs),
        "auto_fixable": auto_fixable,
        "severity_distribution": severity_dist,
        "risk_score": risk_score,
        "providers": state.get("providers", []),
    }

    # LLM enhancement
    report_summary = (
        f"IAM risk score: {risk_score}/100. "
        f"{len(raw_policies)} policies, "
        f"{len(raw_alerts)} over-privileged, "
        f"{len(raw_unused)} unused permissions, "
        f"{len(raw_recs)} recommendations."
    )
    try:
        from .prompts import (
            SYSTEM_IAM_REPORT,
            IAMReportOutput,
        )

        context = json.dumps(stats, default=str)
        llm_result = cast(
            IAMReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_IAM_REPORT,
                user_prompt=(f"IAM posture stats:\n{context}"),
                schema=IAMReportOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="iam_policy_analyzer",
            node="generate_report",
        )
        report_summary = llm_result.summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="iam_policy_analyzer",
            node="generate_report",
        )

    return {
        "stage": IPAStage.REPORT.value,
        "stats": stats,
        "risk_score": risk_score,
        "session_duration_ms": elapsed,
        "current_step": "generate_report",
        "reasoning_chain": state.get("reasoning_chain", []) + [report_summary],
    }
