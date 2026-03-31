"""Node implementations for the Security Gamification
Engine Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_gamification_engine.models import (
    ReasoningStep,
    SecurityGamificationEngineState,
    SGEStage,
)
from shieldops.agents.security_gamification_engine.prompts import (
    SYSTEM_BADGES,
    SYSTEM_CHALLENGES,
    SYSTEM_PERFORMANCE,
    SYSTEM_REPORT,
    BadgeRecommendationOutput,
    ChallengeDesignOutput,
    GamificationReportOutput,
    PerformanceAnalysisOutput,
)
from shieldops.agents.security_gamification_engine.tools import (
    SecurityGamificationEngineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityGamificationEngineToolkit | None = None


def set_toolkit(
    toolkit: SecurityGamificationEngineToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityGamificationEngineToolkit:
    if _toolkit is None:
        return SecurityGamificationEngineToolkit()
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
# Node: define_challenges
# ------------------------------------------------------------------


async def define_challenges(
    state: SecurityGamificationEngineState,
) -> dict[str, Any]:
    """Define security awareness challenges for the
    gamification campaign."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.define_challenges(
        campaign_name=state.campaign_name,
        challenge_types=state.challenge_types,
        config=state.config,
    )

    challenges: list[dict[str, Any]] = list(results)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "campaign": state.campaign_name,
                "types": state.challenge_types,
                "teams": state.target_teams,
                "config": state.config,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_CHALLENGES,
            user_prompt=f"Design challenges for:\n{ctx}",
            schema=ChallengeDesignOutput,
        )
        if llm_out.challenges:  # type: ignore[union-attr]
            challenges = [
                *challenges,
                *llm_out.challenges,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="define_challenges",
            count=len(llm_out.challenges),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="define_challenges",
        )

    step = _step(
        state.reasoning_chain,
        "define_challenges",
        f"Types: {len(state.challenge_types)}, teams={len(state.target_teams)}",
        f"Defined {len(challenges)} challenges",
        start,
        "challenge_store",
    )

    return {
        "challenges": challenges,
        "stage": SGEStage.DEFINE_CHALLENGES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "define_challenges",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: track_participation
# ------------------------------------------------------------------


async def track_participation(
    state: SecurityGamificationEngineState,
) -> dict[str, Any]:
    """Track participant engagement across challenges."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    participation = await toolkit.track_participation(
        challenges=state.challenges,
        target_teams=state.target_teams,
    )

    unique_participants = len({p.get("participant_id") for p in participation})

    step = _step(
        state.reasoning_chain,
        "track_participation",
        f"Tracking {len(state.challenges)} challenges across {len(state.target_teams)} teams",
        f"{len(participation)} records, {unique_participants} participants",
        start,
        "participation_tracker",
    )

    return {
        "participation": participation,
        "total_participants": unique_participants,
        "stage": SGEStage.TRACK_PARTICIPATION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "track_participation",
    }


# ------------------------------------------------------------------
# Node: score_performance
# ------------------------------------------------------------------


async def score_performance(
    state: SecurityGamificationEngineState,
) -> dict[str, Any]:
    """Score participant performance on challenges."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scores = await toolkit.score_performance(
        participation=state.participation,
        challenges=state.challenges,
    )

    scores = list(scores)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "participation_count": len(state.participation),
                "challenge_count": len(state.challenges),
                "sample": state.participation[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_PERFORMANCE,
            user_prompt=f"Analyze performance:\n{ctx}",
            schema=PerformanceAnalysisOutput,
        )
        rand_id = random.randint(1000, 9999)  # noqa: S311
        if llm_out.improvement_areas:  # type: ignore[union-attr]
            scores.append(
                {
                    "analysis_id": f"llm-{rand_id}",
                    "top_performers": llm_out.top_performers,  # type: ignore[union-attr]
                    "improvement_areas": llm_out.improvement_areas,  # type: ignore[union-attr]
                    "avg_accuracy": llm_out.avg_accuracy,  # type: ignore[union-attr]
                    "engagement_score": llm_out.engagement_score,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="score_performance",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="score_performance",
        )

    # Compute avg score
    point_values = [
        s.get("total_score", 0) for s in scores if isinstance(s.get("total_score"), (int, float))
    ]
    avg_score = sum(point_values) / len(point_values) if point_values else 0.0

    completed = sum(1 for p in state.participation if p.get("completed"))
    total = len(state.participation) if state.participation else 1
    completion_rate = completed / total

    step = _step(
        state.reasoning_chain,
        "score_performance",
        f"Scoring {len(state.participation)} participations",
        f"{len(scores)} scores, avg={avg_score:.1f}",
        start,
        "scoring_engine",
    )

    return {
        "scores": scores,
        "avg_score": avg_score,
        "completion_rate": completion_rate,
        "stage": SGEStage.SCORE_PERFORMANCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "score_performance",
    }


# ------------------------------------------------------------------
# Node: update_leaderboard
# ------------------------------------------------------------------


async def update_leaderboard(
    state: SecurityGamificationEngineState,
) -> dict[str, Any]:
    """Update team and individual leaderboards."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    leaderboard = await toolkit.update_leaderboard(
        scores=state.scores,
        target_teams=state.target_teams,
    )

    step = _step(
        state.reasoning_chain,
        "update_leaderboard",
        f"Updating with {len(state.scores)} scores",
        f"Leaderboard has {len(leaderboard)} entries",
        start,
        "leaderboard_store",
    )

    return {
        "leaderboard": leaderboard,
        "stage": SGEStage.UPDATE_LEADERBOARD,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "update_leaderboard",
    }


# ------------------------------------------------------------------
# Node: award_badges
# ------------------------------------------------------------------


async def award_badges(
    state: SecurityGamificationEngineState,
) -> dict[str, Any]:
    """Award achievement badges based on performance
    and leaderboard standings."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    badges = await toolkit.award_badges(
        leaderboard=state.leaderboard,
        scores=state.scores,
    )

    badges = list(badges)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "leaderboard_top": state.leaderboard[:10],
                "scores_sample": state.scores[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_BADGES,
            user_prompt=f"Recommend badges:\n{ctx}",
            schema=BadgeRecommendationOutput,
        )
        if llm_out.recommended_badges:  # type: ignore[union-attr]
            badges.extend(llm_out.recommended_badges)  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="award_badges",
            count=len(llm_out.recommended_badges),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="award_badges",
        )

    step = _step(
        state.reasoning_chain,
        "award_badges",
        f"Evaluating {len(state.leaderboard)} entries",
        f"Awarded {len(badges)} badges",
        start,
        "badge_service",
    )

    return {
        "badges": badges,
        "badges_awarded": len(badges),
        "stage": SGEStage.AWARD_BADGES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "award_badges",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecurityGamificationEngineState,
) -> dict[str, Any]:
    """Generate the final gamification campaign report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "campaign": state.campaign_name,
        "total_participants": state.total_participants,
        "avg_score": state.avg_score,
        "completion_rate": state.completion_rate,
        "badges_awarded": state.badges_awarded,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "campaign": state.campaign_name,
                "participants": state.total_participants,
                "avg_score": state.avg_score,
                "completion_rate": state.completion_rate,
                "badges": state.badges_awarded,
                "leaderboard_top": state.leaderboard[:5],
                "challenges": state.challenges[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate campaign report:\n{ctx}",
            schema=GamificationReportOutput,
        )
        if isinstance(llm_out, GamificationReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "engagement_metrics": llm_out.engagement_metrics,
                    "recommendations": llm_out.recommendations,
                    "risk_areas": llm_out.risk_areas,
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

    await toolkit.record_metric("sge_participants", float(state.total_participants))
    await toolkit.record_metric("sge_completion_rate", state.completion_rate)

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_participants} participants",
        f"Report generated, avg_score={state.avg_score:.1f}",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": SGEStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
