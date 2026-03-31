"""Node implementations for the Toxic Combination
Detector Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.toxic_combination_detector.models import (
    ReasoningStep,
    TCDStage,
    ToxicCombinationDetectorState,
)
from shieldops.agents.toxic_combination_detector.prompts import (
    SYSTEM_BLAST,
    SYSTEM_PERMISSIONS,
    SYSTEM_REPORT,
    SYSTEM_TOXIC,
    BlastRadiusOutput,
    PermissionAnalysisOutput,
    TCDReportOutput,
    ToxicDetectionOutput,
)
from shieldops.agents.toxic_combination_detector.tools import (
    ToxicCombinationDetectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ToxicCombinationDetectorToolkit | None = None


def set_toolkit(
    toolkit: ToxicCombinationDetectorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ToxicCombinationDetectorToolkit:
    if _toolkit is None:
        return ToxicCombinationDetectorToolkit()
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
    state: ToxicCombinationDetectorState,
) -> dict[str, Any]:
    """Collect permission sets across target cloud
    providers and identities."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.collect_permissions(
        providers=state.target_providers,
        identities=state.target_identities,
    )

    permissions: list[dict[str, Any]] = list(results)

    step = _step(
        state.reasoning_chain,
        "collect_permissions",
        f"Providers: {len(state.target_providers)}, identities={len(state.target_identities)}",
        f"Collected {len(permissions)} permission sets",
        start,
        "iam_client",
    )

    return {
        "permissions": permissions,
        "total_identities": len(permissions),
        "stage": TCDStage.COLLECT_PERMISSIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_permissions",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_combinations
# ------------------------------------------------------------------


async def analyze_combinations(
    state: ToxicCombinationDetectorState,
) -> dict[str, Any]:
    """Analyze permission combinations for toxic patterns
    and SoD violations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    combinations = await toolkit.analyze_combinations(
        permissions=state.permissions,
        sod_policies=state.sod_policies,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "identity_count": len(state.permissions),
                "permissions_sample": state.permissions[:5],
                "sod_policies": state.sod_policies,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_PERMISSIONS,
            user_prompt=(f"Analyze permissions:\n{ctx}"),
            schema=PermissionAnalysisOutput,
        )
        if llm_out.high_risk_identities:  # type: ignore[union-attr]
            combinations = [
                *combinations,
                *llm_out.high_risk_identities,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="analyze_combinations",
            count=len(llm_out.high_risk_identities),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_combinations",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_combinations",
        f"Analyzing {len(state.permissions)} permission sets",
        f"Found {len(combinations)} combinations",
        start,
        "permission_analyzer",
    )

    return {
        "combinations": combinations,
        "stage": TCDStage.ANALYZE_COMBINATIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_combinations",
    }


# ------------------------------------------------------------------
# Node: detect_toxic
# ------------------------------------------------------------------


async def detect_toxic(
    state: ToxicCombinationDetectorState,
) -> dict[str, Any]:
    """Detect toxic permission combinations from analyzed
    pairs."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    toxic_combos = await toolkit.detect_toxic(
        combinations=state.combinations,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "combination_count": len(state.combinations),
                "combinations_sample": state.combinations[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_TOXIC,
            user_prompt=f"Detect toxic combos:\n{ctx}",
            schema=ToxicDetectionOutput,
        )
        if llm_out.toxic_combos:  # type: ignore[union-attr]
            toxic_combos.append(
                {
                    "toxic_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "toxic_combos": (llm_out.toxic_combos),  # type: ignore[union-attr]
                    "attack_chains": llm_out.attack_chains,  # type: ignore[union-attr]
                    "severity_distribution": llm_out.severity_distribution,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="detect_toxic",
            combos=len(llm_out.toxic_combos),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_toxic",
        )

    critical_count = sum(1 for t in toxic_combos if t.get("severity") == "critical")

    step = _step(
        state.reasoning_chain,
        "detect_toxic",
        f"Scanning {len(state.combinations)} combinations",
        f"Detected {len(toxic_combos)} toxic, {critical_count} critical",
        start,
        "toxic_detector",
    )

    return {
        "toxic_combos": toxic_combos,
        "total_toxic": len(toxic_combos),
        "critical_toxic": critical_count,
        "stage": TCDStage.DETECT_TOXIC,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_toxic",
    }


# ------------------------------------------------------------------
# Node: assess_blast_radius
# ------------------------------------------------------------------


async def assess_blast_radius(
    state: ToxicCombinationDetectorState,
) -> dict[str, Any]:
    """Assess blast radius for each detected toxic
    combination."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    blast_assessments = await toolkit.assess_blast_radius(
        toxic_combos=state.toxic_combos,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "toxic_count": len(state.toxic_combos),
                "toxic_sample": state.toxic_combos[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_BLAST,
            user_prompt=f"Assess blast radius:\n{ctx}",
            schema=BlastRadiusOutput,
        )
        if llm_out.critical_paths:  # type: ignore[union-attr]
            blast_assessments.append(
                {
                    "assessment_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "max_blast_radius": (llm_out.max_blast_radius),  # type: ignore[union-attr]
                    "critical_paths": llm_out.critical_paths,  # type: ignore[union-attr]
                    "data_exposure": llm_out.data_exposure,  # type: ignore[union-attr]
                    "containment_steps": llm_out.containment_steps,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="assess_blast_radius",
            paths=len(llm_out.critical_paths),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_blast_radius",
        )

    max_radius = max(
        (a.get("blast_radius_score", 0.0) for a in blast_assessments),
        default=0.0,
    )

    step = _step(
        state.reasoning_chain,
        "assess_blast_radius",
        f"Assessing {len(state.toxic_combos)} toxic combos",
        f"Max blast radius: {max_radius:.1f}",
        start,
        "blast_analyzer",
    )

    return {
        "blast_assessments": blast_assessments,
        "max_blast_radius": max_radius,
        "stage": TCDStage.ASSESS_BLAST_RADIUS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_blast_radius",
    }


# ------------------------------------------------------------------
# Node: recommend
# ------------------------------------------------------------------


async def recommend(
    state: ToxicCombinationDetectorState,
) -> dict[str, Any]:
    """Generate remediation recommendations for toxic
    combinations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    recommendations = await toolkit.recommend_fixes(
        toxic_combos=state.toxic_combos,
        blast_assessments=state.blast_assessments,
    )

    step = _step(
        state.reasoning_chain,
        "recommend",
        f"Generating fixes for {len(state.toxic_combos)} toxic combos",
        f"Produced {len(recommendations)} recommendations",
        start,
        "recommendation_engine",
    )

    return {
        "recommendations": recommendations,
        "stage": TCDStage.RECOMMEND,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: ToxicCombinationDetectorState,
) -> dict[str, Any]:
    """Generate the final toxic combination detection
    report with executive summary."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "scan_name": state.scan_name,
        "total_identities": state.total_identities,
        "total_toxic": state.total_toxic,
        "critical_toxic": state.critical_toxic,
        "max_blast_radius": state.max_blast_radius,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "scan_name": state.scan_name,
                "total_identities": state.total_identities,
                "total_toxic": state.total_toxic,
                "critical_toxic": state.critical_toxic,
                "max_blast_radius": state.max_blast_radius,
                "toxic_sample": state.toxic_combos[:5],
                "blast_sample": state.blast_assessments[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate detection report:\n{ctx}"),
            schema=TCDReportOutput,
        )
        if isinstance(llm_out, TCDReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "sod_compliance": llm_out.sod_compliance,
                    "risk_rating": llm_out.risk_rating,
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
    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    await toolkit.record_metric(
        scan_id=state.request_id,
        outcome={
            "total_identities": state.total_identities,
            "total_toxic": state.total_toxic,
            "critical_toxic": state.critical_toxic,
            "max_blast_radius": state.max_blast_radius,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_toxic} toxic combos"),
        (f"Report generated, blast_radius={state.max_blast_radius:.1f}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": TCDStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
