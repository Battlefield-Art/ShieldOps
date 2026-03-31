"""Node implementations for the Cloud Entitlement Manager
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cloud_entitlement_manager.models import (
    CEMStage,
    CloudEntitlementManagerState,
    ReasoningStep,
)
from shieldops.agents.cloud_entitlement_manager.prompts import (
    SYSTEM_LEAST_PRIVILEGE,
    SYSTEM_PERMISSION_ANALYSIS,
    SYSTEM_REPORT,
    SYSTEM_RISK_ASSESSMENT,
    EntitlementReportOutput,
    LeastPrivilegeOutput,
    PermissionAnalysisOutput,
    RiskAssessmentOutput,
)
from shieldops.agents.cloud_entitlement_manager.tools import (
    CloudEntitlementManagerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CloudEntitlementManagerToolkit | None = None


def set_toolkit(
    toolkit: CloudEntitlementManagerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> CloudEntitlementManagerToolkit:
    if _toolkit is None:
        return CloudEntitlementManagerToolkit()
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
# Node: discover_identities
# ------------------------------------------------------------------


async def discover_identities(
    state: CloudEntitlementManagerState,
) -> dict[str, Any]:
    """Discover cloud identities across target providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    providers = [p.value for p in state.target_providers]
    identities = await toolkit.discover_identities(
        providers=providers,
        scope=state.scope,
    )

    step = _step(
        state.reasoning_chain,
        "discover_identities",
        f"Providers: {len(providers)}",
        f"Discovered {len(identities)} identities",
        start,
        "iam_connector",
    )

    return {
        "identities": identities,
        "total_identities": len(identities),
        "stage": CEMStage.DISCOVER_IDENTITIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "discover_identities",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_permissions
# ------------------------------------------------------------------


async def analyze_permissions(
    state: CloudEntitlementManagerState,
) -> dict[str, Any]:
    """Analyze permissions for all discovered identities."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    providers = [p.value for p in state.target_providers]
    analyses = await toolkit.analyze_permissions(
        identities=state.identities,
        providers=providers,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "identity_count": len(state.identities),
                "identities_sample": state.identities[:5],
                "providers": providers,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_PERMISSION_ANALYSIS,
            user_prompt=(f"Analyze permissions:\n{ctx}"),
            schema=PermissionAnalysisOutput,
        )
        if llm_out.excess_permissions:  # type: ignore[union-attr]
            analyses.append(
                {
                    "analysis_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "excess_permissions": llm_out.excess_permissions,  # type: ignore[union-attr]
                    "high_risk_count": llm_out.high_risk_count,  # type: ignore[union-attr]
                    "wildcards": llm_out.wildcards_detected,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_permissions",
            excess=len(llm_out.excess_permissions),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_permissions",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_permissions",
        (f"Analyzing {len(state.identities)} identities across {len(providers)} providers"),
        f"Produced {len(analyses)} analyses",
        start,
        "permission_analyzer",
    )

    return {
        "permission_analyses": analyses,
        "stage": CEMStage.ANALYZE_PERMISSIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_permissions",
    }


# ------------------------------------------------------------------
# Node: detect_excess
# ------------------------------------------------------------------


async def detect_excess(
    state: CloudEntitlementManagerState,
) -> dict[str, Any]:
    """Detect excess permissions from analysis results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    excess = await toolkit.detect_excess(
        analyses=state.permission_analyses,
    )

    step = _step(
        state.reasoning_chain,
        "detect_excess",
        (f"Checking {len(state.permission_analyses)} analyses for excess"),
        f"Found {len(excess)} excess permissions",
        start,
        "permission_analyzer",
    )

    return {
        "excess_permissions": excess,
        "excess_count": len(excess),
        "stage": CEMStage.DETECT_EXCESS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_excess",
    }


# ------------------------------------------------------------------
# Node: assess_risk
# ------------------------------------------------------------------


async def assess_risk(
    state: CloudEntitlementManagerState,
) -> dict[str, Any]:
    """Assess risk from excess permissions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    risk = await toolkit.assess_risk(
        excess_permissions=state.excess_permissions,
        identities=state.identities,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "excess_count": state.excess_count,
                "excess_sample": state.excess_permissions[:5],
                "identity_count": state.total_identities,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_RISK_ASSESSMENT,
            user_prompt=f"Assess risk:\n{ctx}",
            schema=RiskAssessmentOutput,
        )
        if isinstance(llm_out, RiskAssessmentOutput):
            risk.update(
                {
                    "risk_score": llm_out.risk_score,
                    "critical_findings": llm_out.critical_findings,
                    "blast_radius": llm_out.blast_radius,
                    "attack_paths": llm_out.attack_paths,
                }
            )
        logger.info(
            "llm_enhanced",
            node="assess_risk",
            risk_score=llm_out.risk_score,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risk",
        )

    high_risk = risk.get("high_risk_count", 0)

    step = _step(
        state.reasoning_chain,
        "assess_risk",
        (f"Assessing risk for {state.excess_count} excess permissions"),
        (f"Risk score: {risk.get('risk_score', 0):.1f}, {high_risk} high-risk"),
        start,
        "risk_scorer",
    )

    return {
        "risk_assessment": risk,
        "risk_score": risk.get("risk_score", 0.0),
        "high_risk_count": high_risk,
        "stage": CEMStage.ASSESS_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_risk",
    }


# ------------------------------------------------------------------
# Node: recommend_least_privilege
# ------------------------------------------------------------------


async def recommend_least_privilege(
    state: CloudEntitlementManagerState,
) -> dict[str, Any]:
    """Generate least-privilege recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    recs = await toolkit.recommend_least_privilege(
        analyses=state.permission_analyses,
        risk_assessment=state.risk_assessment,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "excess_count": state.excess_count,
                "risk_score": state.risk_score,
                "risk_assessment": state.risk_assessment,
                "analyses_sample": (state.permission_analyses[:5]),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_LEAST_PRIVILEGE,
            user_prompt=(f"Recommend least privilege:\n{ctx}"),
            schema=LeastPrivilegeOutput,
        )
        if llm_out.recommendations:  # type: ignore[union-attr]
            recs = [
                *recs,
                *llm_out.recommendations,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="recommend_least_privilege",
            count=len(llm_out.recommendations),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend_least_privilege",
        )

    step = _step(
        state.reasoning_chain,
        "recommend_least_privilege",
        (f"Generating recommendations for {state.excess_count} excess permissions"),
        f"Produced {len(recs)} recommendations",
        start,
        "policy_generator",
    )

    return {
        "recommendations": recs,
        "stage": CEMStage.RECOMMEND_LEAST_PRIV,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_least_privilege",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: CloudEntitlementManagerState,
) -> dict[str, Any]:
    """Generate the final CIEM report with executive
    summary and recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    report: dict[str, Any] = {
        "total_identities": state.total_identities,
        "excess_count": state.excess_count,
        "high_risk_count": state.high_risk_count,
        "risk_score": state.risk_score,
        "recommendations_count": len(state.recommendations),
        "duration_ms": duration_ms,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "total_identities": state.total_identities,
                "excess_count": state.excess_count,
                "high_risk_count": state.high_risk_count,
                "risk_score": state.risk_score,
                "recommendations": state.recommendations[:5],
                "risk_assessment": state.risk_assessment,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate entitlement report:\n{ctx}"),
            schema=EntitlementReportOutput,
        )
        if isinstance(llm_out, EntitlementReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "compliance_gaps": llm_out.compliance_gaps,
                    "effectiveness_rating": llm_out.effectiveness_rating,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recs=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    await toolkit.record_metric(
        metric_name="cem.run_completed",
        value=state.risk_score,
        tags={
            "excess": str(state.excess_count),
            "high_risk": str(state.high_risk_count),
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_identities} identities, {state.excess_count} excess"),
        (f"Report generated, risk={state.risk_score:.1f}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": CEMStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
