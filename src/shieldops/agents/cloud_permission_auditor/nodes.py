"""Cloud Permission Auditor Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CloudPermission,
    CPAStage,
    PermissionViolation,
    ReasoningStep,
    ScopeAnalysis,
)
from .tools import CloudPermissionAuditorToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Collect Permissions
# ------------------------------------------------------------------


async def collect_permissions(
    state: dict[str, Any],
    toolkit: CloudPermissionAuditorToolkit,
) -> dict[str, Any]:
    """Collect IAM permissions across cloud providers."""
    logger.info("cpa.node.collect_permissions")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    perms = await toolkit.collect_permissions(tenant_id)
    data = [p.model_dump() for p in perms]

    principals = {p.principal for p in perms}
    note = f"Collected {len(perms)} permissions for {len(principals)} principals"

    return {
        "stage": CPAStage.ANALYZE_SCOPE.value,
        "permissions": data,
        "total_principals": len(principals),
        "current_step": "collect_permissions",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="collect_permissions",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Analyze Scope
# ------------------------------------------------------------------


async def analyze_scope(
    state: dict[str, Any],
    toolkit: CloudPermissionAuditorToolkit,
) -> dict[str, Any]:
    """Analyze permission scope for each principal."""
    logger.info("cpa.node.analyze_scope")
    state = _to_dict(state)

    perms = [CloudPermission(**p) for p in state.get("permissions", [])]
    analyses = await toolkit.analyze_scope(perms)
    data = [a.model_dump() for a in analyses]

    note = f"Analyzed scope for {len(analyses)} principals"

    try:
        from .prompts import SYSTEM_SCOPE, ScopeInsight

        ctx = json.dumps(
            {
                "principals": [
                    {
                        "principal": a.principal,
                        "total": a.total_permissions,
                        "unused_pct": a.unused_pct,
                        "risk": a.risk_score,
                        "wildcards": a.wildcard_count,
                    }
                    for a in analyses[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ScopeInsight,
            await llm_structured(
                system_prompt=SYSTEM_SCOPE,
                user_prompt=(f"Permission scope analysis:\n{ctx}"),
                schema=ScopeInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cpa",
            node="analyze_scope",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cpa",
            node="analyze_scope",
        )

    return {
        "stage": CPAStage.DETECT_VIOLATIONS.value,
        "scope_analyses": data,
        "current_step": "analyze_scope",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="analyze_scope",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Detect Violations
# ------------------------------------------------------------------


async def detect_violations(
    state: dict[str, Any],
    toolkit: CloudPermissionAuditorToolkit,
) -> dict[str, Any]:
    """Detect permission violations."""
    logger.info("cpa.node.detect_violations")
    state = _to_dict(state)

    perms = [CloudPermission(**p) for p in state.get("permissions", [])]
    scope_analyses = [ScopeAnalysis(**a) for a in state.get("scope_analyses", [])]
    violations = await toolkit.detect_violations(
        perms,
        scope_analyses,
    )
    data = [v.model_dump() for v in violations]

    critical = sum(1 for v in violations if v.severity == "critical")
    note = f"Found {len(violations)} violations, {critical} critical"

    try:
        from .prompts import (
            SYSTEM_VIOLATIONS,
            ViolationInsight,
        )

        ctx = json.dumps(
            {
                "violations": [
                    {
                        "principal": v.principal,
                        "type": v.violation_type.value,
                        "severity": v.severity,
                        "risk": v.risk_score,
                    }
                    for v in violations[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ViolationInsight,
            await llm_structured(
                system_prompt=SYSTEM_VIOLATIONS,
                user_prompt=(f"Violation detection:\n{ctx}"),
                schema=ViolationInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cpa",
            node="detect_violations",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cpa",
            node="detect_violations",
        )

    return {
        "stage": CPAStage.MAP_CROSS_ACCOUNT.value,
        "violations": data,
        "total_violations": len(violations),
        "critical_violations": critical,
        "current_step": "detect_violations",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_violations",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Map Cross-Account Access
# ------------------------------------------------------------------


async def map_cross_account(
    state: dict[str, Any],
    toolkit: CloudPermissionAuditorToolkit,
) -> dict[str, Any]:
    """Map cross-account access relationships."""
    logger.info("cpa.node.map_cross_account")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    entries = await toolkit.map_cross_account(tenant_id)
    data = [e.model_dump() for e in entries]

    external = sum(1 for e in entries if e.is_external)
    note = f"Mapped {len(entries)} cross-account relationships, {external} external"

    try:
        from .prompts import (
            SYSTEM_CROSS_ACCOUNT,
            CrossAccountInsight,
        )

        ctx = json.dumps(
            {
                "cross_account": [
                    {
                        "source": e.source_account,
                        "target": e.target_account,
                        "principal": e.principal,
                        "external": e.is_external,
                        "risk": e.risk_score,
                    }
                    for e in entries[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            CrossAccountInsight,
            await llm_structured(
                system_prompt=SYSTEM_CROSS_ACCOUNT,
                user_prompt=(f"Cross-account analysis:\n{ctx}"),
                schema=CrossAccountInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cpa",
            node="map_cross_account",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cpa",
            node="map_cross_account",
        )

    return {
        "stage": CPAStage.GENERATE_FIXES.value,
        "cross_account_access": data,
        "current_step": "map_cross_account",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="map_cross_account",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Generate Fixes
# ------------------------------------------------------------------


async def generate_fixes(
    state: dict[str, Any],
    toolkit: CloudPermissionAuditorToolkit,
) -> dict[str, Any]:
    """Generate remediation fixes for violations."""
    logger.info("cpa.node.generate_fixes")
    state = _to_dict(state)

    violations = [PermissionViolation(**v) for v in state.get("violations", [])]
    fixes = await toolkit.generate_fixes(violations)
    data = [f.model_dump() for f in fixes]

    auto = sum(1 for f in fixes if f.auto_applicable)
    note = f"Generated {len(fixes)} fixes, {auto} auto-applicable"

    return {
        "stage": CPAStage.REPORT.value,
        "fixes": data,
        "current_step": "generate_fixes",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="generate_fixes",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: CloudPermissionAuditorToolkit,
) -> dict[str, Any]:
    """Compile the final permission audit report."""
    logger.info("cpa.node.report")
    state = _to_dict(state)

    total_principals = state.get(
        "total_principals",
        0,
    )
    total_violations = state.get(
        "total_violations",
        0,
    )
    critical = state.get("critical_violations", 0)
    fix_count = len(state.get("fixes", []))
    xa_count = len(
        state.get("cross_account_access", []),
    )

    lines = [
        "# Cloud Permission Audit Report",
        "",
        f"**Total principals:** {total_principals}",
        f"**Total violations:** {total_violations}",
        f"**Critical violations:** {critical}",
        f"**Cross-account links:** {xa_count}",
        f"**Remediation fixes:** {fix_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "principals": total_principals,
                "violations": total_violations,
                "critical": critical,
                "cross_account": xa_count,
                "fixes": fix_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Permission audit report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cpa",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cpa",
            node="report",
        )

    return {
        "stage": CPAStage.REPORT.value,
        "report": report_text,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
