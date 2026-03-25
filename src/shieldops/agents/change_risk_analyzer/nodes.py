"""Change Risk Analyzer Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AnalyzerStage,
    BlastRadiusPrediction,
    ChangeRequest,
    RiskAssessment,
)
from .tools import ChangeRiskAnalyzerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def collect_change(
    state: dict[str, Any], toolkit: ChangeRiskAnalyzerToolkit
) -> dict[str, Any]:
    """Collect and validate incoming change requests."""
    logger.info("change_risk_analyzer.node.collect_change")
    state = _to_dict(state)

    raw_changes = state.get("change_requests", [])
    if not raw_changes:
        # Generate sample changes for demonstration
        raw_changes = [{"title": "Sample deployment", "environment": "staging"}]

    # Normalize to dicts for the toolkit
    change_dicts: list[dict[str, Any]] = []
    for c in raw_changes:
        if isinstance(c, ChangeRequest):
            change_dicts.append(c.model_dump())
        elif isinstance(c, dict):
            change_dicts.append(c)

    return {
        "stage": AnalyzerStage.ANALYZE_DIFF.value,
        "change_requests": change_dicts,
        "session_start": state.get("session_start", time.time()),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(change_dicts)} change request(s) for analysis"],
    }


async def analyze_diff(state: dict[str, Any], toolkit: ChangeRiskAnalyzerToolkit) -> dict[str, Any]:
    """Analyze change diffs and enrich change request data."""
    logger.info("change_risk_analyzer.node.analyze_diff")
    state = _to_dict(state)

    raw_changes = state.get("change_requests", [])
    enriched = await toolkit.analyze_change_diff(raw_changes)
    enriched_dicts = [c.model_dump() for c in enriched]

    reasoning_note = f"Analyzed diffs for {len(enriched)} change(s)"

    # LLM enhancement: intelligent diff analysis
    try:
        from .prompts import SYSTEM_ANALYZE_DIFF, RiskAnalysisResult

        diff_context = json.dumps(
            {
                "total_changes": len(enriched),
                "changes_summary": [
                    {
                        "title": c.title,
                        "change_type": c.change_type.value,
                        "files_changed": c.files_changed,
                        "lines_added": c.lines_added,
                        "lines_removed": c.lines_removed,
                        "services_affected": c.services_affected,
                        "environment": c.environment,
                    }
                    for c in enriched[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RiskAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE_DIFF,
                user_prompt=f"Change diff analysis context:\n{diff_context}",
                schema=RiskAnalysisResult,
            ),
        )
        logger.info("llm_enhanced", agent="change_risk_analyzer", node="analyze_diff")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="change_risk_analyzer", node="analyze_diff")

    return {
        "stage": AnalyzerStage.ASSESS_RISK.value,
        "change_requests": enriched_dicts,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def assess_risk(state: dict[str, Any], toolkit: ChangeRiskAnalyzerToolkit) -> dict[str, Any]:
    """Score risk for each change request."""
    logger.info("change_risk_analyzer.node.assess_risk")
    state = _to_dict(state)

    raw_changes = state.get("change_requests", [])
    changes = [ChangeRequest(**c) for c in raw_changes]

    assessments = await toolkit.assess_risk(changes)
    assessment_dicts = [a.model_dump() for a in assessments]

    reasoning_note = (
        f"Assessed risk for {len(assessments)} change(s) — "
        f"scores: {[round(a.risk_score, 2) for a in assessments]}"
    )

    # LLM enhancement: intelligent risk assessment
    try:
        from .prompts import SYSTEM_ASSESS_RISK, RiskAnalysisResult

        risk_context = json.dumps(
            {
                "assessments": [
                    {
                        "change_id": a.change_id,
                        "risk_level": a.risk_level.value,
                        "risk_score": a.risk_score,
                        "risk_factors": a.risk_factors,
                    }
                    for a in assessments[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RiskAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_ASSESS_RISK,
                user_prompt=f"Risk assessment context:\n{risk_context}",
                schema=RiskAnalysisResult,
            ),
        )
        logger.info("llm_enhanced", agent="change_risk_analyzer", node="assess_risk")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="change_risk_analyzer", node="assess_risk")

    return {
        "stage": AnalyzerStage.PREDICT_BLAST_RADIUS.value,
        "risk_assessments": assessment_dicts,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def predict_blast_radius(
    state: dict[str, Any], toolkit: ChangeRiskAnalyzerToolkit
) -> dict[str, Any]:
    """Predict blast radius for each change."""
    logger.info("change_risk_analyzer.node.predict_blast_radius")
    state = _to_dict(state)

    raw_changes = state.get("change_requests", [])
    changes = [ChangeRequest(**c) for c in raw_changes]

    predictions = await toolkit.predict_blast_radius(changes)
    prediction_dicts = [p.model_dump() for p in predictions]

    reasoning_note = (
        f"Predicted blast radius for {len(predictions)} change(s) — "
        f"max affected services: "
        f"{max((len(p.affected_services) for p in predictions), default=0)}"
    )

    # LLM enhancement: blast radius analysis
    try:
        from .prompts import SYSTEM_PREDICT_BLAST_RADIUS, BlastRadiusResult

        blast_context = json.dumps(
            {
                "predictions": [
                    {
                        "change_id": p.change_id,
                        "affected_services": p.affected_services,
                        "affected_users_estimate": p.affected_users_estimate,
                        "cascading_failures": p.cascading_failures,
                    }
                    for p in predictions[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            BlastRadiusResult,
            await llm_structured(
                system_prompt=SYSTEM_PREDICT_BLAST_RADIUS,
                user_prompt=f"Blast radius prediction context:\n{blast_context}",
                schema=BlastRadiusResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="change_risk_analyzer",
            node="predict_blast_radius",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="change_risk_analyzer",
            node="predict_blast_radius",
        )

    return {
        "stage": AnalyzerStage.RECOMMEND.value,
        "blast_radius_predictions": prediction_dicts,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def recommend(state: dict[str, Any], toolkit: ChangeRiskAnalyzerToolkit) -> dict[str, Any]:
    """Generate approval/rollback recommendations."""
    logger.info("change_risk_analyzer.node.recommend")
    state = _to_dict(state)

    raw_assessments = state.get("risk_assessments", [])
    raw_predictions = state.get("blast_radius_predictions", [])

    assessments = [RiskAssessment(**a) for a in raw_assessments]
    predictions = [BlastRadiusPrediction(**p) for p in raw_predictions]

    recommendations = await toolkit.generate_recommendations(assessments, predictions)
    rec_dicts = [r.model_dump() for r in recommendations]

    # Summarize decisions
    decisions = [r.approval_decision.value for r in recommendations]
    reasoning_note = f"Generated {len(recommendations)} recommendation(s) — decisions: {decisions}"

    # LLM enhancement: recommendation refinement
    try:
        from .prompts import SYSTEM_RECOMMEND, RecommendationResult

        rec_context = json.dumps(
            {
                "recommendations": [
                    {
                        "change_id": r.change_id,
                        "decision": r.approval_decision.value,
                        "reasoning": r.reasoning,
                        "canary_suggested": r.canary_suggested,
                    }
                    for r in recommendations[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RecommendationResult,
            await llm_structured(
                system_prompt=SYSTEM_RECOMMEND,
                user_prompt=f"Recommendation context:\n{rec_context}",
                schema=RecommendationResult,
            ),
        )
        logger.info("llm_enhanced", agent="change_risk_analyzer", node="recommend")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="change_risk_analyzer", node="recommend")

    return {
        "stage": AnalyzerStage.REPORT.value,
        "recommendations": rec_dicts,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(
    state: dict[str, Any], toolkit: ChangeRiskAnalyzerToolkit
) -> dict[str, Any]:
    """Generate final risk analysis report with aggregate statistics."""
    logger.info("change_risk_analyzer.node.generate_report")
    state = _to_dict(state)

    raw_assessments = state.get("risk_assessments", [])
    raw_predictions = state.get("blast_radius_predictions", [])
    raw_recs = state.get("recommendations", [])
    raw_changes = state.get("change_requests", [])

    # Compute aggregate statistics
    risk_scores = [a.get("risk_score", 0.0) for a in raw_assessments]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 4) if risk_scores else 0.0
    max_risk = round(max(risk_scores), 4) if risk_scores else 0.0

    decisions = [r.get("approval_decision", "") for r in raw_recs]
    blocked = sum(1 for d in decisions if d == "block")
    auto_approved = sum(1 for d in decisions if d == "auto_approve")

    total_affected_users = sum(p.get("affected_users_estimate", 0) for p in raw_predictions)

    session_start = state.get("session_start", time.time())
    duration_ms = round((time.time() - session_start) * 1000, 1)

    stats: dict[str, Any] = {
        "total_changes_analyzed": len(raw_changes),
        "average_risk_score": avg_risk,
        "max_risk_score": max_risk,
        "changes_blocked": blocked,
        "changes_auto_approved": auto_approved,
        "changes_requiring_review": len(raw_recs) - blocked - auto_approved,
        "total_affected_users_estimate": total_affected_users,
        "analysis_duration_ms": duration_ms,
    }

    return {
        "stage": AnalyzerStage.REPORT.value,
        "stats": stats,
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report complete — {len(raw_changes)} changes analyzed, "
            f"avg risk {avg_risk:.2f}, {blocked} blocked, "
            f"{auto_approved} auto-approved"
        ],
    }
