"""Node implementations for the Security Training Platform."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_training_platform.models import (
    ReasoningStep,
    SecurityTrainingPlatformState,
    STPStage,
)
from shieldops.agents.security_training_platform.prompts import (
    SYSTEM_BASELINE,
    SYSTEM_CAMPAIGN,
    SYSTEM_RISK,
    SYSTEM_SIMULATE,
    SYSTEM_TRACK,
    BaselineOutput,
    CampaignDesignOutput,
    RiskScoreOutput,
    SimulationOutput,
    TrackingOutput,
)
from shieldops.agents.security_training_platform.tools import (
    SecurityTrainingPlatformToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityTrainingPlatformToolkit | None = None


def set_toolkit(
    toolkit: SecurityTrainingPlatformToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityTrainingPlatformToolkit:
    if _toolkit is None:
        return SecurityTrainingPlatformToolkit()
    return _toolkit


def _step(
    state: SecurityTrainingPlatformState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Create a reasoning step."""
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def assess_baseline(
    state: SecurityTrainingPlatformState,
) -> dict[str, Any]:
    """Assess baseline security awareness."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.assess_baseline(state.training_config)
    avg = sum(a.get("avg_awareness_score", 0) for a in raw) / max(len(raw), 1)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "teams": state.training_config.get("teams", [])[:10],
                "assessment_count": len(raw),
                "avg_awareness": round(avg, 1),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_BASELINE,
            user_prompt=f"Baseline assessment:\n{ctx}",
            schema=BaselineOutput,
        )
        if hasattr(llm_result, "avg_awareness") and llm_result.avg_awareness > 0:
            avg = round((avg + llm_result.avg_awareness) / 2, 1)
        logger.info(
            "llm_enhanced",
            node="assess_baseline",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_baseline",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "assess_baseline",
        f"teams={len(raw)}",
        f"avg awareness={round(avg, 1)}",
        elapsed,
        "user_directory",
    )
    await toolkit.record_metric("baseline_avg", avg)

    return {
        "baseline_assessments": raw,
        "avg_awareness": round(avg, 1),
        "stage": STPStage.CREATE_CAMPAIGN,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "assess_baseline",
        "session_start": start,
    }


async def create_campaign(
    state: SecurityTrainingPlatformState,
) -> dict[str, Any]:
    """Create training campaigns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    campaigns = await toolkit.create_campaign(
        state.baseline_assessments,
        state.training_config,
    )
    total_users = sum(c.get("target_user_count", 0) for c in campaigns)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "baseline_count": len(state.baseline_assessments),
                "campaigns": campaigns[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CAMPAIGN,
            user_prompt=f"Campaign design:\n{ctx}",
            schema=CampaignDesignOutput,
        )
        if hasattr(llm_result, "total_users") and llm_result.total_users > total_users:
            total_users = llm_result.total_users
        logger.info(
            "llm_enhanced",
            node="create_campaign",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="create_campaign",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "create_campaign",
        f"creating for {len(state.baseline_assessments)} teams",
        f"{len(campaigns)} campaigns, {total_users} users",
        elapsed,
        "lms_client",
    )

    return {
        "campaigns": campaigns,
        "total_targeted_users": total_users,
        "stage": STPStage.DEPLOY_SIMULATION,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "create_campaign",
    }


async def deploy_simulation(
    state: SecurityTrainingPlatformState,
) -> dict[str, Any]:
    """Deploy training simulations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.deploy_simulation(state.campaigns)
    click_rate = sum(1 for r in results if r.get("clicked_link")) / max(len(results), 1)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "campaign_count": len(state.campaigns),
                "result_count": len(results),
                "click_rate": round(click_rate, 2),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SIMULATE,
            user_prompt=f"Simulation results:\n{ctx}",
            schema=SimulationOutput,
        )
        if hasattr(llm_result, "click_rate"):
            logger.info(
                "llm_enhanced",
                node="deploy_simulation",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="deploy_simulation",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "deploy_simulation",
        f"deploying {len(state.campaigns)} campaigns",
        f"{len(results)} results, click_rate={round(click_rate, 2)}",
        elapsed,
        "email_sender",
    )

    return {
        "simulation_results": results,
        "overall_click_rate": round(click_rate, 2),
        "stage": STPStage.TRACK_RESULTS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "deploy_simulation",
    }


async def track_results(
    state: SecurityTrainingPlatformState,
) -> dict[str, Any]:
    """Track and aggregate results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    tracked = await toolkit.track_results(
        state.simulation_results,
    )
    completion = sum(1 for r in tracked if r.get("score", 0) > 0) / max(len(tracked), 1)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "result_count": len(tracked),
                "completion_rate": round(completion, 2),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_TRACK,
            user_prompt=f"Result tracking:\n{ctx}",
            schema=TrackingOutput,
        )
        if hasattr(llm_result, "completion_rate"):
            logger.info(
                "llm_enhanced",
                node="track_results",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="track_results",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "track_results",
        f"tracking {len(state.simulation_results)} results",
        f"completion={round(completion, 2)}",
        elapsed,
        "analytics_store",
    )

    return {
        "tracked_results": tracked,
        "completion_rate": round(completion, 2),
        "stage": STPStage.SCORE_RISK,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "track_results",
    }


async def score_risk(
    state: SecurityTrainingPlatformState,
) -> dict[str, Any]:
    """Score risk for users and teams."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scores = await toolkit.score_risk(state.tracked_results)
    high_risk = sum(1 for s in scores if s.get("risk_tier") in ("critical", "high"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "result_count": len(state.tracked_results),
                "scores": scores[:10],
                "high_risk": high_risk,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RISK,
            user_prompt=f"Risk scoring context:\n{ctx}",
            schema=RiskScoreOutput,
        )
        if hasattr(llm_result, "high_risk_count") and llm_result.high_risk_count > high_risk:
            high_risk = llm_result.high_risk_count
        logger.info(
            "llm_enhanced",
            node="score_risk",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="score_risk",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "score_risk",
        f"scoring {len(state.tracked_results)} results",
        f"{high_risk} high-risk entities",
        elapsed,
        "risk_engine",
    )
    await toolkit.record_metric("high_risk_count", float(high_risk))

    return {
        "risk_scores": scores,
        "high_risk_count": high_risk,
        "stage": STPStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "score_risk",
    }


async def generate_report(
    state: SecurityTrainingPlatformState,
) -> dict[str, Any]:
    """Generate final training report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "teams_assessed": len(state.baseline_assessments),
        "avg_awareness": state.avg_awareness,
        "campaigns_created": len(state.campaigns),
        "total_targeted": state.total_targeted_users,
        "overall_click_rate": state.overall_click_rate,
        "completion_rate": state.completion_rate,
        "high_risk_entities": state.high_risk_count,
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("training_duration_ms", float(duration_ms))
    await toolkit.record_metric("click_rate", state.overall_click_rate)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing training {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
