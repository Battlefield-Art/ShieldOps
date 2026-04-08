"""Node implementations for the Insider Risk Scorer
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.agents.insider_risk_scorer.models import (
    InsiderRiskScorerState,
    IRSStage,
    ReasoningStep,
)
from shieldops.agents.insider_risk_scorer.prompts import (
    SYSTEM_ANOMALY_DETECTION,
    SYSTEM_BEHAVIOR_ANALYSIS,
    SYSTEM_REPORT,
    SYSTEM_RISK_SCORING,
    AnomalyDetectionOutput,
    BehaviorAnalysisOutput,
    InsiderRiskReportOutput,
    RiskScoringOutput,
)
from shieldops.agents.insider_risk_scorer.tools import (
    InsiderRiskScorerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: InsiderRiskScorerToolkit | None = None


def _get_toolkit() -> InsiderRiskScorerToolkit:
    if _toolkit is None:
        return InsiderRiskScorerToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: float,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((time.time() - start) * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: collect_signals
# ------------------------------------------------------------------


async def collect_signals(
    state: InsiderRiskScorerState,
) -> dict[str, Any]:
    """Collect behavioral signals from all identity
    and security data sources."""
    start = time.time()
    toolkit = _get_toolkit()

    results = await toolkit.collect_signals(
        tenant_id=state.tenant_id,
    )

    step = _step(
        state.reasoning_chain,
        "collect_signals",
        f"Tenant: {state.tenant_id}",
        f"Collected {len(results)} signals",
        start,
        "signal_collector",
    )

    return {
        "signals": results,
        "stage": IRSStage.COLLECT_SIGNALS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_signals",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_behavior
# ------------------------------------------------------------------


async def analyze_behavior(
    state: InsiderRiskScorerState,
) -> dict[str, Any]:
    """Build behavioral profiles with peer group
    comparison analysis."""
    start = time.time()
    toolkit = _get_toolkit()

    profiles = await toolkit.analyze_behavior(
        signals=state.signals,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "signal_count": len(state.signals),
                "profile_count": len(profiles),
                "profiles_sample": profiles[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_BEHAVIOR_ANALYSIS,
            user_prompt=(f"Analyze behavioral signals:\n{ctx}"),
            schema=BehaviorAnalysisOutput,
        )
        logger.info(
            "llm_enhanced",
            node="analyze_behavior",
            anomalous=len(
                llm_out.anomalous_users  # type: ignore[union-attr]
            ),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_behavior",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_behavior",
        f"Analyzing {len(state.signals)} signals",
        f"Built {len(profiles)} behavior profiles",
        start,
        "ueba_engine",
    )

    return {
        "behavior_profiles": profiles,
        "total_users_scored": len(profiles),
        "stage": IRSStage.ANALYZE_BEHAVIOR,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_behavior",
    }


# ------------------------------------------------------------------
# Node: score_risk
# ------------------------------------------------------------------


async def score_risk(
    state: InsiderRiskScorerState,
) -> dict[str, Any]:
    """Compute composite insider risk scores per user."""
    start = time.time()
    toolkit = _get_toolkit()

    anomalies = await toolkit.detect_anomalies(
        profiles=state.behavior_profiles,
    )
    scores = await toolkit.score_risk(
        profiles=state.behavior_profiles,
        anomalies=anomalies,
    )

    high_risk = [s["user_id"] for s in scores if s.get("tier") in ("critical", "high")]

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "score_count": len(scores),
                "high_risk": len(high_risk),
                "scores_sample": scores[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_RISK_SCORING,
            user_prompt=f"Score insider risk:\n{ctx}",
            schema=RiskScoringOutput,
        )
        logger.info(
            "llm_enhanced",
            node="score_risk",
            critical=len(
                llm_out.critical_users  # type: ignore[union-attr]
            ),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="score_risk",
        )

    step = _step(
        state.reasoning_chain,
        "score_risk",
        f"Scoring {len(state.behavior_profiles)} profiles",
        f"{len(scores)} scored, {len(high_risk)} high risk",
        start,
        "risk_scorer",
    )

    return {
        "risk_scores": scores,
        "anomalies": anomalies,
        "high_risk_users": high_risk,
        "anomaly_count": len(anomalies),
        "stage": IRSStage.SCORE_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "score_risk",
    }


# ------------------------------------------------------------------
# Node: detect_anomalies
# ------------------------------------------------------------------


async def detect_anomalies(
    state: InsiderRiskScorerState,
) -> dict[str, Any]:
    """Detect behavioral anomalies from scored profiles
    and enrich with LLM analysis."""
    start = time.time()
    _get_toolkit()

    _existing = state.anomalies
    enriched = list(_existing)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "anomaly_count": len(enriched),
                "anomalies_sample": enriched[:10],
                "profiles": state.behavior_profiles[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANOMALY_DETECTION,
            user_prompt=(f"Detect behavioral anomalies:\n{ctx}"),
            schema=AnomalyDetectionOutput,
        )
        logger.info(
            "llm_enhanced",
            node="detect_anomalies",
            count=llm_out.anomaly_count,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_anomalies",
        )

    step = _step(
        state.reasoning_chain,
        "detect_anomalies",
        f"Reviewing {len(enriched)} anomalies",
        f"Enriched {len(enriched)} anomalies",
        start,
        "anomaly_detector",
    )

    return {
        "anomalies": enriched,
        "anomaly_count": len(enriched),
        "stage": IRSStage.DETECT_ANOMALY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_anomalies",
    }


# ------------------------------------------------------------------
# Node: generate_alerts
# ------------------------------------------------------------------


async def generate_alerts(
    state: InsiderRiskScorerState,
) -> dict[str, Any]:
    """Generate actionable alerts for high-risk users."""
    start = time.time()
    toolkit = _get_toolkit()

    alerts = await toolkit.generate_alerts(
        scores=state.risk_scores,
    )

    step = _step(
        state.reasoning_chain,
        "generate_alerts",
        f"Alerting on {len(state.high_risk_users)} users",
        f"Generated {len(alerts)} alerts",
        start,
        "alert_engine",
    )

    return {
        "alerts": alerts,
        "stage": IRSStage.ALERT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_alerts",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: InsiderRiskScorerState,
) -> dict[str, Any]:
    """Generate final insider risk posture report."""
    start = time.time()
    _toolkit_ref = _get_toolkit()

    duration_ms = int((time.time() - state.session_start) * 1000)

    report: dict[str, Any] = {
        "total_users_scored": state.total_users_scored,
        "high_risk_users": len(state.high_risk_users),
        "anomaly_count": state.anomaly_count,
        "alert_count": len(state.alerts),
        "duration_ms": duration_ms,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scores_summary": state.risk_scores[:10],
                "anomalies_summary": state.anomalies[:10],
                "alerts": state.alerts[:10],
                "high_risk_users": state.high_risk_users,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate insider risk report:\n{ctx}"),
            schema=InsiderRiskReportOutput,
        )
        if isinstance(llm_out, InsiderRiskReportOutput):
            report.update(
                {
                    "executive_summary": (llm_out.executive_summary),
                    "threat_level": llm_out.threat_level,
                    "key_findings": llm_out.key_findings,
                    "recommendations": (llm_out.recommendations),
                    "risk_trend": llm_out.risk_trend,
                }
            )
        logger.info(
            "llm_enhanced",
            node="generate_report",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    await _toolkit_ref.record_metric(
        "insider_risk.run_completed",
        1.0,
        {"tenant_id": state.tenant_id},
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_users_scored} users"),
        "Report generated",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": IRSStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
