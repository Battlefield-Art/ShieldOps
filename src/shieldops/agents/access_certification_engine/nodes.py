"""Node implementations for the Access Certification
Engine Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.access_certification_engine.models import (
    AccessCertificationEngineState,
    ACEStage,
    ReasoningStep,
)
from shieldops.agents.access_certification_engine.prompts import (
    SYSTEM_EXCESS,
    SYSTEM_REPORT,
    SYSTEM_USAGE,
    CertificationReportOutput,
    ExcessIdentificationOutput,
    UsageAnalysisOutput,
)
from shieldops.agents.access_certification_engine.tools import (
    AccessCertificationEngineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AccessCertificationEngineToolkit | None = None


def set_toolkit(
    toolkit: AccessCertificationEngineToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> AccessCertificationEngineToolkit:
    if _toolkit is None:
        return AccessCertificationEngineToolkit()
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
# Node: collect_entitlements
# ------------------------------------------------------------------


async def collect_entitlements(
    state: AccessCertificationEngineState,
) -> dict[str, Any]:
    """Collect user entitlements from configured identity
    sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    entitlements = await toolkit.collect_entitlements(
        identity_sources=state.identity_sources,
        scope=state.scope,
    )

    step = _step(
        state.reasoning_chain,
        "collect_entitlements",
        f"Sources: {len(state.identity_sources)}",
        f"Collected {len(entitlements)} entitlements",
        start,
        "identity_provider",
    )

    return {
        "entitlements": entitlements,
        "total_entitlements": len(entitlements),
        "stage": ACEStage.COLLECT_ENTITLEMENTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_entitlements",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_usage
# ------------------------------------------------------------------


async def analyze_usage(
    state: AccessCertificationEngineState,
) -> dict[str, Any]:
    """Analyze entitlement usage patterns over the review
    period."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_usage(
        entitlements=state.entitlements,
        period_days=state.review_period_days,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "entitlement_count": len(state.entitlements),
                "period_days": state.review_period_days,
                "sample": state.entitlements[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_USAGE,
            user_prompt=f"Analyze usage:\n{ctx}",
            schema=UsageAnalysisOutput,
        )
        if llm_out.dormant_entitlements:  # type: ignore[union-attr]
            analyses.append(
                {
                    "analysis_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "dormant": llm_out.dormant_entitlements,  # type: ignore[union-attr]
                    "excess": llm_out.excess_permissions,  # type: ignore[union-attr]
                    "sod_violations": llm_out.sod_violations,  # type: ignore[union-attr]
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_usage",
            dormant=len(llm_out.dormant_entitlements),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_usage",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_usage",
        f"Analyzing {len(state.entitlements)} entitlements",
        f"Produced {len(analyses)} usage analyses",
        start,
        "usage_tracker",
    )

    return {
        "usage_analyses": analyses,
        "stage": ACEStage.ANALYZE_USAGE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_usage",
    }


# ------------------------------------------------------------------
# Node: identify_excess
# ------------------------------------------------------------------


async def identify_excess(
    state: AccessCertificationEngineState,
) -> dict[str, Any]:
    """Identify excess permissions and SOD violations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    excess = await toolkit.identify_excess(
        usage_analyses=state.usage_analyses,
        entitlements=state.entitlements,
    )

    # LLM enhancement per excess candidate
    enhanced: list[dict[str, Any]] = list(excess)
    for item in state.usage_analyses:
        try:
            ctx = _json.dumps(
                {"usage_analysis": item},
                default=str,
            )
            llm_out = await llm_structured(
                system_prompt=SYSTEM_EXCESS,
                user_prompt=f"Identify excess:\n{ctx}",
                schema=ExcessIdentificationOutput,
            )
            _rid = random.randint(1000, 9999)  # noqa: S311
            enhanced.append(
                {
                    "permission_id": f"llm-{_rid}",
                    "reason": llm_out.reason,  # type: ignore[union-attr]
                    "risk_level": llm_out.risk_level,  # type: ignore[union-attr]
                    "confidence": llm_out.confidence,  # type: ignore[union-attr]
                    "action": llm_out.recommended_action,  # type: ignore[union-attr]
                    "sod_conflict": llm_out.sod_conflict,  # type: ignore[union-attr]
                }
            )
            logger.info(
                "llm_enhanced",
                node="identify_excess",
                risk=llm_out.risk_level,  # type: ignore[union-attr]
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="identify_excess",
            )

    sod_count = sum(1 for e in enhanced if isinstance(e, dict) and e.get("sod_conflict"))

    step = _step(
        state.reasoning_chain,
        "identify_excess",
        f"Checking {len(state.usage_analyses)} analyses",
        f"Found {len(enhanced)} excess, {sod_count} SOD",
        start,
        "sod_checker",
    )

    return {
        "excess_permissions": enhanced,
        "excess_found": len(enhanced),
        "sod_violations": sod_count,
        "stage": ACEStage.IDENTIFY_EXCESS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_excess",
    }


# ------------------------------------------------------------------
# Node: generate_reviews
# ------------------------------------------------------------------


async def generate_reviews(
    state: AccessCertificationEngineState,
) -> dict[str, Any]:
    """Generate access review campaigns grouped by
    reviewer."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    campaigns = await toolkit.generate_reviews(
        excess_permissions=state.excess_permissions,
        scope=state.scope,
    )

    step = _step(
        state.reasoning_chain,
        "generate_reviews",
        f"Creating reviews for {len(state.excess_permissions)} excess",
        f"Generated {len(campaigns)} campaigns",
        start,
        "review_platform",
    )

    return {
        "review_campaigns": campaigns,
        "stage": ACEStage.GENERATE_REVIEWS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_reviews",
    }


# ------------------------------------------------------------------
# Node: process_decisions
# ------------------------------------------------------------------


async def process_decisions(
    state: AccessCertificationEngineState,
) -> dict[str, Any]:
    """Process review decisions and detect rubber-stamping."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    decisions = await toolkit.process_decisions(
        review_campaigns=state.review_campaigns,
    )

    revocations = sum(1 for d in decisions if isinstance(d, dict) and d.get("decision") == "revoke")

    step = _step(
        state.reasoning_chain,
        "process_decisions",
        f"Processing {len(state.review_campaigns)} campaigns",
        f"{len(decisions)} decisions, {revocations} revocations",
        start,
        "review_platform",
    )

    return {
        "decisions": decisions,
        "revocations_recommended": revocations,
        "stage": ACEStage.PROCESS_DECISIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "process_decisions",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: AccessCertificationEngineState,
) -> dict[str, Any]:
    """Generate the final access certification report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    report: dict[str, Any] = {
        "campaign": state.campaign_name,
        "total_entitlements": state.total_entitlements,
        "excess_found": state.excess_found,
        "revocations_recommended": state.revocations_recommended,
        "sod_violations": state.sod_violations,
        "duration_ms": duration_ms,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "campaign": state.campaign_name,
                "total_entitlements": state.total_entitlements,
                "excess_found": state.excess_found,
                "sod_violations": state.sod_violations,
                "excess_sample": state.excess_permissions[:10],
                "decisions": state.decisions[:10],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate certification report:\n{ctx}",
            schema=CertificationReportOutput,
        )
        if isinstance(llm_out, CertificationReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "rubber_stamp_rate": llm_out.rubber_stamp_rate,
                    "top_risks": llm_out.top_risks,
                    "recommendations": llm_out.recommendations,
                    "compliance_status": llm_out.compliance_status,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recommendations=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metrics
    await toolkit.record_metric(
        request_id=state.request_id,
        outcome={
            "total_entitlements": state.total_entitlements,
            "excess_found": state.excess_found,
            "revocations": state.revocations_recommended,
            "sod_violations": state.sod_violations,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.excess_found} excess permissions",
        f"Report generated, revocations={state.revocations_recommended}",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": ACEStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
