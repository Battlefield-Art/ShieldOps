"""Node implementations for the Cloud Permission
Optimizer Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cloud_permission_optimizer.models import (
    CloudPermissionOptimizerState,
    CPOStage,
    ReasoningStep,
)
from shieldops.agents.cloud_permission_optimizer.prompts import (
    SYSTEM_EXCESS_DETECTION,
    SYSTEM_LEAST_PRIVILEGE,
    SYSTEM_REPORT,
    SYSTEM_USAGE_ANALYSIS,
    ExcessDetectionOutput,
    LeastPrivilegeOutput,
    PermissionReportOutput,
    UsageAnalysisOutput,
)
from shieldops.agents.cloud_permission_optimizer.tools import (
    CloudPermissionOptimizerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CloudPermissionOptimizerToolkit | None = None


def _get_toolkit() -> CloudPermissionOptimizerToolkit:
    if _toolkit is None:
        return CloudPermissionOptimizerToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: datetime,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: collect_permissions
# ------------------------------------------------------------------


async def collect_permissions(
    state: CloudPermissionOptimizerState,
) -> dict[str, Any]:
    """Collect permission grants across target cloud
    providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    providers = [p.value for p in state.target_providers]
    results = await toolkit.collect_permissions(
        providers=providers,
        scope=state.scope,
    )

    permissions: list[dict[str, Any]] = list(results)

    step = _step(
        state.reasoning_chain,
        "collect_permissions",
        f"Providers: {len(providers)}",
        f"Collected {len(permissions)} permission grants",
        start,
        "iam_client",
    )

    return {
        "permissions": permissions,
        "total_permissions": len(permissions),
        "stage": CPOStage.COLLECT_PERMISSIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_permissions",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_usage
# ------------------------------------------------------------------


async def analyze_usage(
    state: CloudPermissionOptimizerState,
) -> dict[str, Any]:
    """Analyze permission usage against audit logs."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    usage = await toolkit.analyze_usage(
        permissions=state.permissions,
        lookback_days=state.lookback_days,
    )

    usage_records: list[dict[str, Any]] = list(usage)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "permission_count": len(state.permissions),
                "lookback_days": state.lookback_days,
                "sample": state.permissions[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_USAGE_ANALYSIS,
            user_prompt=f"Analyze permission usage:\n{ctx}",
            schema=UsageAnalysisOutput,
        )
        if llm_out.high_risk_grants:  # type: ignore[union-attr]
            _rand = random.randint(1000, 9999)  # noqa: S311
            usage_records.append(
                {
                    "analysis_id": f"llm-{_rand}",
                    "active": llm_out.active_permissions,  # type: ignore[union-attr]
                    "unused": llm_out.unused_permissions,  # type: ignore[union-attr]
                    "high_risk": llm_out.high_risk_grants,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_usage",
            high_risk=len(llm_out.high_risk_grants),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_usage",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_usage",
        f"Analyzing {len(state.permissions)} permissions",
        f"Produced {len(usage_records)} usage records",
        start,
        "usage_analyzer",
    )

    return {
        "usage_records": usage_records,
        "stage": CPOStage.ANALYZE_USAGE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_usage",
    }


# ------------------------------------------------------------------
# Node: detect_excess
# ------------------------------------------------------------------


async def detect_excess(
    state: CloudPermissionOptimizerState,
) -> dict[str, Any]:
    """Detect over-privileged permission grants."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    excess = await toolkit.detect_excess(
        permissions=state.permissions,
        usage=state.usage_records,
    )

    excess_list: list[dict[str, Any]] = list(excess)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "permissions_sample": state.permissions[:5],
                "usage_sample": state.usage_records[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_EXCESS_DETECTION,
            user_prompt=f"Detect excess permissions:\n{ctx}",
            schema=ExcessDetectionOutput,
        )
        if llm_out.excess_items:  # type: ignore[union-attr]
            for idx, item in enumerate(llm_out.excess_items):  # type: ignore[union-attr]
                excess_list.append(
                    {
                        "excess_id": f"llm-{idx}",
                        "principal": item.get("principal", ""),
                        "permission": item.get("action", ""),
                        "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    }
                )
        logger.info(
            "llm_enhanced",
            node="detect_excess",
            excess=len(llm_out.excess_items),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_excess",
        )

    step = _step(
        state.reasoning_chain,
        "detect_excess",
        f"Scanning {len(state.permissions)} permissions",
        f"Found {len(excess_list)} excess grants",
        start,
        "risk_scorer",
    )

    return {
        "excess_permissions": excess_list,
        "excess_count": len(excess_list),
        "stage": CPOStage.DETECT_EXCESS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_excess",
    }


# ------------------------------------------------------------------
# Node: calculate_least_privilege
# ------------------------------------------------------------------


async def calculate_least_privilege(
    state: CloudPermissionOptimizerState,
) -> dict[str, Any]:
    """Calculate least-privilege policies for each
    over-privileged principal."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    policies = await toolkit.calculate_least_privilege(
        excess=state.excess_permissions,
        usage=state.usage_records,
    )

    policy_list: list[dict[str, Any]] = list(policies)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "excess_count": len(state.excess_permissions),
                "excess_sample": state.excess_permissions[:5],
                "usage_sample": state.usage_records[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_LEAST_PRIVILEGE,
            user_prompt=(f"Calculate least-privilege policies:\n{ctx}"),
            schema=LeastPrivilegeOutput,
        )
        if llm_out.policies:  # type: ignore[union-attr]
            policy_list = [
                *policy_list,
                *llm_out.policies,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="calculate_least_privilege",
            policies=len(llm_out.policies),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="calculate_least_privilege",
        )

    total_perms = state.total_permissions if state.total_permissions > 0 else 1
    reduction = (state.excess_count / total_perms) * 100.0

    step = _step(
        state.reasoning_chain,
        "calculate_least_privilege",
        f"Computing policies for {state.excess_count} excess",
        f"Generated {len(policy_list)} policies, {reduction:.1f}% reduction",
        start,
        "policy_generator",
    )

    return {
        "least_privilege_policies": policy_list,
        "reduction_pct": reduction,
        "stage": CPOStage.CALCULATE_LEAST_PRIV,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "calculate_least_privilege",
    }


# ------------------------------------------------------------------
# Node: recommend_changes
# ------------------------------------------------------------------


async def recommend_changes(
    state: CloudPermissionOptimizerState,
) -> dict[str, Any]:
    """Generate prioritized right-sizing recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    recs = await toolkit.recommend_changes(
        policies=state.least_privilege_policies,
        excess=state.excess_permissions,
    )

    step = _step(
        state.reasoning_chain,
        "recommend_changes",
        f"Generating recs for {len(state.least_privilege_policies)} policies",
        f"Produced {len(recs)} recommendations",
        start,
        "recommendation_engine",
    )

    return {
        "recommendations": recs,
        "stage": CPOStage.RECOMMEND,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_changes",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: CloudPermissionOptimizerState,
) -> dict[str, Any]:
    """Generate the final permission optimization report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    risk_score = min(
        10.0,
        state.excess_count * 0.5 + (1.0 if state.reduction_pct > 50 else 0.0),
    )

    report: dict[str, Any] = {
        "total_permissions": state.total_permissions,
        "excess_count": state.excess_count,
        "reduction_pct": state.reduction_pct,
        "risk_score": risk_score,
        "recommendations_count": len(state.recommendations),
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "total_permissions": state.total_permissions,
                "excess_count": state.excess_count,
                "reduction_pct": state.reduction_pct,
                "recommendations_sample": state.recommendations[:5],
                "policies_sample": state.least_privilege_policies[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate optimization report:\n{ctx}",
            schema=PermissionReportOutput,
        )
        if isinstance(llm_out, PermissionReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "top_risks": llm_out.top_risks,
                    "recommendations": llm_out.recommendations,
                    "compliance_impact": llm_out.compliance_impact,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                risks=len(llm_out.top_risks),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metrics
    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    await toolkit.record_metric(
        request_id=state.request_id,
        outcome={
            "total_permissions": state.total_permissions,
            "excess_count": state.excess_count,
            "reduction_pct": state.reduction_pct,
            "risk_score": risk_score,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_permissions} permissions",
        f"Report generated, risk={risk_score:.1f}",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "risk_score": risk_score,
        "session_duration_ms": duration_ms,
        "stage": CPOStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
