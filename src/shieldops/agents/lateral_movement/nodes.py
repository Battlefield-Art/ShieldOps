"""Lateral Movement Detector Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    BlastRadiusAssessment,
    DetectorStage,
    IdentitySignal,
    MovementPath,
)
from .tools import LateralMovementToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def collect_signals(state: dict[str, Any], toolkit: LateralMovementToolkit) -> dict[str, Any]:
    """Collect identity signals from all cloud providers."""
    logger.info("lateral_movement.node.collect_signals")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    time_window = state.get("time_window_hours", 24)
    session_start = time.time()

    signals = await toolkit.collect_identity_signals(
        tenant_id=tenant_id,
        time_window_hours=time_window,
    )
    signal_dicts = [s.model_dump() for s in signals]

    return {
        "identity_signals": signal_dicts,
        "stage": DetectorStage.COLLECT_SIGNALS.value,
        "session_start": session_start,
        "current_step": "collect_signals",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(signals)} identity signals for tenant {tenant_id}"],
    }


async def analyze_paths(state: dict[str, Any], toolkit: LateralMovementToolkit) -> dict[str, Any]:
    """Analyze identity signals to identify movement paths."""
    logger.info("lateral_movement.node.analyze_paths")
    state = _to_dict(state)
    raw_signals = state.get("identity_signals", [])

    signals = [IdentitySignal(**s) for s in raw_signals]
    paths = await toolkit.analyze_movement_paths(signals)
    path_dicts = [p.model_dump() for p in paths]

    reasoning_note = f"Analyzed {len(signals)} signals, found {len(paths)} movement paths"

    # LLM enhancement: deeper path analysis
    try:
        from .prompts import SYSTEM_PATH_ANALYSIS, PathAnalysisOutput

        analysis_context = json.dumps(
            {
                "signal_count": len(signals),
                "path_count": len(paths),
                "paths_summary": [
                    {
                        "type": p.movement_type.value,
                        "source": p.source_identity,
                        "target": p.target_identity,
                        "hops": p.hops,
                        "confidence": p.confidence,
                        "mitre": p.mitre_technique,
                    }
                    for p in paths[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PathAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_PATH_ANALYSIS,
                user_prompt=f"Identity movement data:\n{analysis_context}",
                schema=PathAnalysisOutput,
            ),
        )
        logger.info("llm_enhanced", agent="lateral_movement", node="analyze_paths")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="lateral_movement", node="analyze_paths")

    return {
        "movement_paths": path_dicts,
        "stage": DetectorStage.ANALYZE_PATHS.value,
        "current_step": "analyze_paths",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def detect_pivots(state: dict[str, Any], toolkit: LateralMovementToolkit) -> dict[str, Any]:
    """Enrich movement paths with pivot detection and confidence scoring."""
    logger.info("lateral_movement.node.detect_pivots")
    state = _to_dict(state)
    raw_paths = state.get("movement_paths", [])

    # Enrich paths: flag high-confidence pivots and compute stats
    pivot_count = 0
    escalation_count = 0
    federation_count = 0

    for path_dict in raw_paths:
        mt = path_dict.get("movement_type", "")
        if mt == "service_account_pivot":
            pivot_count += 1
        elif mt == "cross_cloud_escalation":
            escalation_count += 1
        elif mt == "federation_abuse":
            federation_count += 1

    stats = {
        "total_paths": len(raw_paths),
        "pivot_count": pivot_count,
        "escalation_count": escalation_count,
        "federation_count": federation_count,
        "high_confidence_count": sum(1 for p in raw_paths if p.get("confidence", 0) >= 0.85),
        "critical_count": sum(
            1 for p in raw_paths if p.get("confidence", 0) >= 0.9 and p.get("hops", 0) >= 3
        ),
    }

    return {
        "stats": stats,
        "stage": DetectorStage.DETECT_PIVOTS.value,
        "current_step": "detect_pivots",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Pivot detection: {pivot_count} SA pivots, "
            f"{escalation_count} cross-cloud escalations, "
            f"{federation_count} federation abuses"
        ],
    }


async def assess_blast_radius(
    state: dict[str, Any], toolkit: LateralMovementToolkit
) -> dict[str, Any]:
    """Assess the blast radius of detected movement paths."""
    logger.info("lateral_movement.node.assess_blast_radius")
    state = _to_dict(state)
    raw_paths = state.get("movement_paths", [])

    paths = [MovementPath(**p) for p in raw_paths]
    assessments = await toolkit.assess_blast_radius(paths)
    assessment_dicts = [a.model_dump() for a in assessments]

    reasoning_note = (
        f"Assessed blast radius for {len(paths)} paths: "
        f"{sum(len(a.affected_resources) for a in assessments)} resources affected"
    )

    # LLM enhancement: deeper blast radius analysis
    try:
        from .prompts import SYSTEM_BLAST_RADIUS, BlastRadiusOutput

        blast_context = json.dumps(
            {
                "path_count": len(paths),
                "assessments": [
                    {
                        "path_id": a.path_id,
                        "severity": a.severity.value,
                        "affected_resources": a.affected_resources[:10],
                        "affected_identities": a.affected_identities[:10],
                        "containment_actions": a.containment_actions,
                    }
                    for a in assessments[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            BlastRadiusOutput,
            await llm_structured(
                system_prompt=SYSTEM_BLAST_RADIUS,
                user_prompt=f"Blast radius data:\n{blast_context}",
                schema=BlastRadiusOutput,
            ),
        )
        logger.info("llm_enhanced", agent="lateral_movement", node="assess_blast_radius")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="lateral_movement", node="assess_blast_radius")

    return {
        "blast_radius_assessments": assessment_dicts,
        "stage": DetectorStage.ASSESS_BLAST_RADIUS.value,
        "current_step": "assess_blast_radius",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def respond(state: dict[str, Any], toolkit: LateralMovementToolkit) -> dict[str, Any]:
    """Execute response actions for detected movement paths."""
    logger.info("lateral_movement.node.respond")
    state = _to_dict(state)
    raw_paths = state.get("movement_paths", [])
    raw_assessments = state.get("blast_radius_assessments", [])

    paths = [MovementPath(**p) for p in raw_paths]
    assessments = [BlastRadiusAssessment(**a) for a in raw_assessments]
    actions = await toolkit.execute_response(paths, assessments)
    action_dicts = [a.model_dump() for a in actions]

    reasoning_note = (
        f"Response: {len(actions)} actions, "
        f"{sum(1 for a in actions if a.auto_executed)} auto-executed, "
        f"{sum(1 for a in actions if a.success)} successful"
    )

    # LLM enhancement: response planning validation
    try:
        from .prompts import SYSTEM_RESPONSE_PLANNING, MovementResponseOutput

        response_context = json.dumps(
            {
                "paths": [
                    {
                        "type": p.movement_type.value,
                        "confidence": p.confidence,
                        "hops": p.hops,
                    }
                    for p in paths[:10]
                ],
                "actions_taken": [
                    {
                        "action_type": a.action_type,
                        "auto_executed": a.auto_executed,
                        "success": a.success,
                    }
                    for a in actions[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            MovementResponseOutput,
            await llm_structured(
                system_prompt=SYSTEM_RESPONSE_PLANNING,
                user_prompt=f"Response context:\n{response_context}",
                schema=MovementResponseOutput,
            ),
        )
        logger.info("llm_enhanced", agent="lateral_movement", node="respond")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="lateral_movement", node="respond")

    return {
        "response_actions": action_dicts,
        "stage": DetectorStage.RESPOND.value,
        "current_step": "respond",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(state: dict[str, Any], toolkit: LateralMovementToolkit) -> dict[str, Any]:
    """Generate the final detection report."""
    logger.info("lateral_movement.node.generate_report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    paths = state.get("movement_paths", [])
    assessments = state.get("blast_radius_assessments", [])
    actions = state.get("response_actions", [])
    stats = state.get("stats", {})

    reasoning_note = (
        f"Report complete: {len(paths)} movement paths detected, "
        f"{len(assessments)} blast radius assessments, "
        f"{len(actions)} response actions"
    )

    # LLM enhancement: executive summary
    try:
        from .prompts import SYSTEM_DETECTION_SUMMARY, DetectionSummaryOutput

        summary_context = json.dumps(
            {
                "stats": stats,
                "path_count": len(paths),
                "assessment_count": len(assessments),
                "action_count": len(actions),
                "paths_summary": [
                    {
                        "type": p.get("movement_type", ""),
                        "confidence": p.get("confidence", 0),
                        "source_cloud": p.get("source_cloud", ""),
                        "target_cloud": p.get("target_cloud", ""),
                    }
                    for p in paths[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            DetectionSummaryOutput,
            await llm_structured(
                system_prompt=SYSTEM_DETECTION_SUMMARY,
                user_prompt=f"Detection summary data:\n{summary_context}",
                schema=DetectionSummaryOutput,
            ),
        )
        logger.info("llm_enhanced", agent="lateral_movement", node="generate_report")
        reasoning_note = f"{llm_result.executive_summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="lateral_movement", node="generate_report")

    return {
        "stage": DetectorStage.REPORT.value,
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }
