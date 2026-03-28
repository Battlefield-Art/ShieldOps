"""Node implementations for Purple Team Orchestrator."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.purple_team_orchestrator.models import (
    ExerciseType,
    PurpleStage,
    PurpleTeamOrchestratorState,
)
from shieldops.agents.purple_team_orchestrator.prompts import (
    SYSTEM_DETECTION_ANALYSIS,
    SYSTEM_EXERCISE_PLAN,
    SYSTEM_EXERCISE_REPORT,
    DetectionAnalysisOutput,
    ExercisePlanOutput,
    ExerciseReportOutput,
)
from shieldops.agents.purple_team_orchestrator.tools import (
    PurpleTeamOrchestratorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: PurpleTeamOrchestratorToolkit | None = None


def set_toolkit(
    toolkit: PurpleTeamOrchestratorToolkit,
) -> None:
    """Inject the toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> PurpleTeamOrchestratorToolkit:
    if _toolkit is None:
        return PurpleTeamOrchestratorToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# -------------------------------------------------------
# Node 1: plan_exercise
# -------------------------------------------------------
async def plan_exercise(
    state: PurpleTeamOrchestratorState,
) -> dict[str, Any]:
    """Plan the purple team exercise."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "purple_team.plan_exercise",
        tenant_id=state.tenant_id,
    )

    ex_type = state.plan.exercise_type or ExerciseType.SIMULATION
    plan = await toolkit.create_plan(ex_type, state.tenant_id)

    user_prompt = (
        f"Exercise type: {ex_type.value}\n"
        f"Tenant: {state.tenant_id}\n"
        f"Scenarios: {', '.join(plan.attack_scenarios)}"
    )
    try:
        result = cast(
            ExercisePlanOutput,
            await llm_structured(
                system_prompt=SYSTEM_EXERCISE_PLAN,
                user_prompt=user_prompt,
                schema=ExercisePlanOutput,
            ),
        )
        plan.objectives = result.objectives[:8]
        plan.attack_scenarios = result.attack_scenarios[:10]
        plan.expected_detections = result.expected_detections[:10]
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="plan_exercise",
            error=str(exc),
        )

    chain_entry = f"Planned exercise '{plan.name}' with {len(plan.attack_scenarios)} scenarios"

    return {
        "plan": plan,
        "stage": PurpleStage.EXECUTE_ATTACKS,
        "reasoning_chain": [chain_entry],
        "current_step": "plan_exercise",
        "session_start": start,
    }


# -------------------------------------------------------
# Node 2: execute_attacks
# -------------------------------------------------------
async def execute_attacks(
    state: PurpleTeamOrchestratorState,
) -> dict[str, Any]:
    """Execute red team attacks."""
    toolkit = _get_toolkit()

    logger.info(
        "purple_team.execute_attacks",
        plan_id=state.plan.id,
    )

    attacks = await toolkit.execute_attacks(state.plan)
    successful = sum(1 for a in attacks if a.success)

    chain_entry = f"Executed {len(attacks)} attacks, {successful} successful"

    return {
        "attacks_executed": attacks,
        "stage": PurpleStage.MONITOR_DETECTIONS,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "execute_attacks",
    }


# -------------------------------------------------------
# Node 3: monitor_detections
# -------------------------------------------------------
async def monitor_detections(
    state: PurpleTeamOrchestratorState,
) -> dict[str, Any]:
    """Monitor blue team detections."""
    toolkit = _get_toolkit()

    logger.info(
        "purple_team.monitor_detections",
        attack_count=len(state.attacks_executed),
    )

    detections = await toolkit.monitor_detections(state.attacks_executed)

    # LLM analysis
    lines = ["## Detection Results"]
    for d in detections:
        lines.append(
            f"- {d.id}: attack={d.attack_id} detected={d.detected} ttd={d.time_to_detect_sec}s"
        )
    user_prompt = "\n".join(lines)

    try:
        result = cast(
            DetectionAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_DETECTION_ANALYSIS,
                user_prompt=user_prompt,
                schema=DetectionAnalysisOutput,
            ),
        )
        coverage = result.coverage_pct
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="monitor_detections",
            error=str(exc),
        )
        detected_count = sum(1 for d in detections if d.detected)
        total = len(detections)
        coverage = round(detected_count / total * 100, 1) if total else 0.0

    chain_entry = f"Monitored {len(detections)} detection points, {coverage}% coverage"

    return {
        "detections_observed": detections,
        "stage": PurpleStage.ASSESS_RESPONSES,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "monitor_detections",
    }


# -------------------------------------------------------
# Node 4: assess_responses
# -------------------------------------------------------
async def assess_responses(
    state: PurpleTeamOrchestratorState,
) -> dict[str, Any]:
    """Assess blue team response quality."""
    toolkit = _get_toolkit()

    logger.info(
        "purple_team.assess_responses",
        detection_count=len(state.detections_observed),
    )

    responses = await toolkit.assess_responses(state.detections_observed)
    contained = sum(1 for r in responses if r.containment_effective)

    chain_entry = f"Assessed {len(responses)} responses, {contained} contained effectively"

    return {
        "responses_assessed": responses,
        "stage": PurpleStage.SCORE_EXERCISE,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "assess_responses",
    }


# -------------------------------------------------------
# Node 5: score_exercise
# -------------------------------------------------------
async def score_exercise(
    state: PurpleTeamOrchestratorState,
) -> dict[str, Any]:
    """Score the exercise performance."""
    toolkit = _get_toolkit()

    logger.info("purple_team.score_exercise")

    scores = await toolkit.score_exercise(
        state.attacks_executed,
        state.detections_observed,
        state.responses_assessed,
    )

    # Calculate team scores
    total_pts = sum(s.points for s in scores)
    total_max = sum(s.max_points for s in scores)
    blue_score = round(total_pts / total_max * 100, 1) if total_max else 0.0

    successful_attacks = sum(1 for a in state.attacks_executed if a.success)
    total_attacks = len(state.attacks_executed)
    red_score = (
        round(
            successful_attacks / total_attacks * 100,
            1,
        )
        if total_attacks
        else 0.0
    )

    chain_entry = f"Scored exercise: red={red_score}% blue={blue_score}%"

    return {
        "scores": scores,
        "red_team_score": red_score,
        "blue_team_score": blue_score,
        "stage": PurpleStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "score_exercise",
    }


# -------------------------------------------------------
# Node 6: report
# -------------------------------------------------------
async def report(
    state: PurpleTeamOrchestratorState,
) -> dict[str, Any]:
    """Generate final exercise report."""
    logger.info(
        "purple_team.report",
        red_score=state.red_team_score,
        blue_score=state.blue_team_score,
    )

    lines = [
        "## Purple Team Exercise Report",
        f"- Exercise: {state.plan.name}",
        f"- Attacks: {len(state.attacks_executed)}",
        f"- Detections: {len(state.detections_observed)}",
        f"- Responses: {len(state.responses_assessed)}",
        f"- Red team score: {state.red_team_score}%",
        f"- Blue team score: {state.blue_team_score}%",
    ]
    for entry in state.reasoning_chain:
        lines.append(f"- {entry}")
    user_prompt = "\n".join(lines)

    try:
        result = cast(
            ExerciseReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_EXERCISE_REPORT,
                user_prompt=user_prompt,
                schema=ExerciseReportOutput,
            ),
        )
        summary = result.executive_summary
        recs = result.top_recommendations
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="report",
            error=str(exc),
        )
        summary = (
            f"Purple team exercise complete: "
            f"red={state.red_team_score}% "
            f"blue={state.blue_team_score}%"
        )
        recs = []

    duration = 0
    if state.session_start:
        duration = _elapsed_ms(state.session_start)

    stats = {
        "exercise_name": state.plan.name,
        "exercise_type": state.plan.exercise_type,
        "attacks": len(state.attacks_executed),
        "detections": len(state.detections_observed),
        "responses": len(state.responses_assessed),
        "red_team_score": state.red_team_score,
        "blue_team_score": state.blue_team_score,
        "summary": summary[:500],
        "recommendations": recs[:5],
    }

    chain_entry = f"Report: red={state.red_team_score}% blue={state.blue_team_score}%"

    return {
        "stats": stats,
        "stage": PurpleStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "complete",
        "session_duration_ms": duration,
    }
