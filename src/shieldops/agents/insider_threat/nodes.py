"""Insider Threat Detection Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    BehavioralBaseline,
    BehaviorDeviation,
    InsiderRiskScore,
    InsiderStage,
    UserSignal,
)
from .tools import InsiderThreatToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def collect_user_signals(
    state: dict[str, Any],
    toolkit: InsiderThreatToolkit,
) -> dict[str, Any]:
    """Collect user signals from all data sources."""
    logger.info("insider_threat.node.collect_user_signals")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    time_window = state.get("time_window_hours", 24)
    session_start = time.time()

    signals = await toolkit.collect_user_signals(
        tenant_id=tenant_id,
        time_window_hours=time_window,
    )
    signal_dicts = [s.model_dump() for s in signals]

    # Identify unique monitored users
    users = list({s.user_id for s in signals})

    return {
        "user_signals": signal_dicts,
        "users_monitored": users,
        "stage": InsiderStage.COLLECT_USER_SIGNALS.value,
        "session_start": session_start,
        "current_step": "collect_user_signals",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(signals)} signals for {len(users)} users in tenant {tenant_id}"],
    }


async def build_behavioral_baseline(
    state: dict[str, Any],
    toolkit: InsiderThreatToolkit,
) -> dict[str, Any]:
    """Build behavioral baselines for each user."""
    logger.info("insider_threat.node.build_behavioral_baseline")
    state = _to_dict(state)
    raw_signals = state.get("user_signals", [])
    signals = [UserSignal(**s) for s in raw_signals]

    baselines = await toolkit.build_baselines(signals)
    baseline_dicts = [b.model_dump() for b in baselines]

    return {
        "baselines_built": baseline_dicts,
        "stage": (InsiderStage.BUILD_BEHAVIORAL_BASELINE.value),
        "current_step": "build_behavioral_baseline",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Built baselines for {len(baselines)} users"],
    }


async def detect_deviations(
    state: dict[str, Any],
    toolkit: InsiderThreatToolkit,
) -> dict[str, Any]:
    """Detect behavioral deviations from baselines."""
    logger.info("insider_threat.node.detect_deviations")
    state = _to_dict(state)
    raw_signals = state.get("user_signals", [])
    raw_baselines = state.get("baselines_built", [])

    signals = [UserSignal(**s) for s in raw_signals]
    baselines = [BehavioralBaseline(**b) for b in raw_baselines]

    deviations = await toolkit.detect_deviations(signals, baselines)
    dev_dicts = [d.model_dump() for d in deviations]

    reasoning_note = f"Detected {len(deviations)} deviations across {len(baselines)} users"

    # LLM enhancement: deviation analysis
    try:
        from .prompts import (
            SYSTEM_DEVIATION_ANALYSIS,
            DeviationAnalysisOutput,
        )

        context = json.dumps(
            {
                "deviation_count": len(deviations),
                "deviations_summary": [
                    {
                        "user_id": d.user_id,
                        "indicator": d.indicator.value,
                        "severity": d.severity,
                        "confidence": d.confidence,
                        "description": d.description,
                    }
                    for d in deviations[:15]
                ],
            },
            default=str,
        )
        llm_result = cast(
            DeviationAnalysisOutput,
            await llm_structured(
                system_prompt=(SYSTEM_DEVIATION_ANALYSIS),
                user_prompt=(f"Behavioral deviations:\n{context}"),
                schema=DeviationAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="insider_threat",
            node="detect_deviations",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="insider_threat",
            node="detect_deviations",
        )

    return {
        "deviations_detected": dev_dicts,
        "stage": InsiderStage.DETECT_DEVIATIONS.value,
        "current_step": "detect_deviations",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def assess_risk(
    state: dict[str, Any],
    toolkit: InsiderThreatToolkit,
) -> dict[str, Any]:
    """Assess composite risk scores for each user."""
    logger.info("insider_threat.node.assess_risk")
    state = _to_dict(state)
    raw_devs = state.get("deviations_detected", [])

    deviations = [BehaviorDeviation(**d) for d in raw_devs]
    scores = await toolkit.assess_risk_scores(deviations)
    score_dicts = [s.model_dump() for s in scores]

    high_risk = [s.user_id for s in scores if s.overall_score >= 0.75]

    reasoning_note = f"Risk assessment: {len(scores)} users scored, {len(high_risk)} high-risk"

    # LLM enhancement: risk analysis
    try:
        from .prompts import (
            SYSTEM_RISK_ASSESSMENT,
            RiskAssessmentOutput,
        )

        context = json.dumps(
            {
                "score_count": len(scores),
                "scores_summary": [
                    {
                        "user_id": s.user_id,
                        "overall_score": s.overall_score,
                        "category": s.category.value,
                        "deviation_count": (s.deviation_count),
                        "high_severity_count": (s.high_severity_count),
                    }
                    for s in scores[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RiskAssessmentOutput,
            await llm_structured(
                system_prompt=SYSTEM_RISK_ASSESSMENT,
                user_prompt=(f"Risk scores:\n{context}"),
                schema=RiskAssessmentOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="insider_threat",
            node="assess_risk",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="insider_threat",
            node="assess_risk",
        )

    return {
        "risk_scores": score_dicts,
        "high_risk_users": high_risk,
        "stage": InsiderStage.ASSESS_RISK.value,
        "current_step": "assess_risk",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def investigate(
    state: dict[str, Any],
    toolkit: InsiderThreatToolkit,
) -> dict[str, Any]:
    """Open investigations for high-risk users."""
    logger.info("insider_threat.node.investigate")
    state = _to_dict(state)
    raw_scores = state.get("risk_scores", [])
    raw_devs = state.get("deviations_detected", [])

    scores = [InsiderRiskScore(**s) for s in raw_scores]
    deviations = [BehaviorDeviation(**d) for d in raw_devs]

    investigations = await toolkit.open_investigations(scores, deviations)
    inv_dicts = [i.model_dump() for i in investigations]

    reasoning_note = f"Opened {len(investigations)} investigations for high-risk users"

    # LLM enhancement: investigation planning
    try:
        from .prompts import (
            SYSTEM_INVESTIGATION,
            InvestigationOutput,
        )

        context = json.dumps(
            {
                "investigation_count": len(investigations),
                "investigations": [
                    {
                        "user_id": inv.user_id,
                        "risk_score": inv.risk_score,
                        "category": inv.category.value,
                        "evidence_count": len(inv.evidence),
                    }
                    for inv in investigations[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            InvestigationOutput,
            await llm_structured(
                system_prompt=SYSTEM_INVESTIGATION,
                user_prompt=(f"Investigation data:\n{context}"),
                schema=InvestigationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="insider_threat",
            node="investigate",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="insider_threat",
            node="investigate",
        )

    return {
        "investigations": inv_dicts,
        "stage": InsiderStage.INVESTIGATE.value,
        "current_step": "investigate",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: InsiderThreatToolkit,
) -> dict[str, Any]:
    """Generate the final insider threat report."""
    logger.info("insider_threat.node.generate_report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    users = state.get("users_monitored", [])
    devs = state.get("deviations_detected", [])
    scores = state.get("risk_scores", [])
    invs = state.get("investigations", [])
    high_risk = state.get("high_risk_users", [])

    stats = {
        "users_monitored": len(users),
        "deviations_detected": len(devs),
        "risk_scores_computed": len(scores),
        "investigations_opened": len(invs),
        "high_risk_users": len(high_risk),
    }

    reasoning_note = (
        f"Report: {len(users)} users monitored, {len(devs)} deviations, {len(invs)} investigations"
    )

    # LLM enhancement: executive summary
    try:
        from .prompts import (
            SYSTEM_REPORT,
            InsiderReportOutput,
        )

        context = json.dumps(
            {
                "stats": stats,
                "high_risk_users": high_risk[:10],
                "deviation_summary": [
                    {
                        "indicator": d.get("indicator", ""),
                        "severity": d.get("severity", 0),
                        "user_id": d.get("user_id", ""),
                    }
                    for d in devs[:10]
                ],
                "score_summary": [
                    {
                        "user_id": s.get("user_id", ""),
                        "overall_score": s.get("overall_score", 0),
                        "category": s.get("category", ""),
                    }
                    for s in scores[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            InsiderReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Insider threat data:\n{context}"),
                schema=InsiderReportOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="insider_threat",
            node="generate_report",
        )
        reasoning_note = f"{llm_result.executive_summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="insider_threat",
            node="generate_report",
        )

    return {
        "stats": stats,
        "stage": InsiderStage.REPORT.value,
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }
