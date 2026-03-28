"""Node implementations for the Incident Simulator Agent LangGraph workflow.

Each node is an async function that:
1. Calls toolkit tools to design, inject, observe, and score
2. Uses the LLM to enhance analysis and reporting
3. Updates the simulation state
4. Records reasoning steps in the audit trail
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.incident_simulator.models import (
    IncidentSimulatorState,
    SimStage,
)
from shieldops.agents.incident_simulator.prompts import (
    SYSTEM_DESIGN_EXERCISE,
    SYSTEM_INJECT_SCENARIO,
    SYSTEM_OBSERVE,
    SYSTEM_REPORT,
    SYSTEM_SCORE_READINESS,
    ExerciseDesignOutput,
    ObservationOutput,
    ReadinessOutput,
    ReportOutput,
    ScenarioOutput,
)
from shieldops.agents.incident_simulator.tools import (
    IncidentSimulatorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit reference, set by the runner at graph construction time.
_toolkit: IncidentSimulatorToolkit | None = None


def set_toolkit(toolkit: IncidentSimulatorToolkit) -> None:
    """Configure the toolkit used by all nodes. Called once at startup."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> IncidentSimulatorToolkit:
    if _toolkit is None:
        return IncidentSimulatorToolkit()
    return _toolkit


async def design_scenario(
    state: IncidentSimulatorState,
) -> dict[str, Any]:
    """Design the simulation exercise and plan injects."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "simulator.design_scenario",
        scenario_type=state.scenario_type,
        exercise_mode=state.exercise_mode,
    )

    scenario_input: dict[str, Any] = {
        "type": state.scenario_type.value,
        "scope": (
            "tabletop"
            if state.exercise_mode == "tabletop"
            else "functional"
            if state.exercise_mode == "functional"
            else "full_scale"
            if state.exercise_mode == "full_scale"
            else "tabletop"
        ),
        "name": f"{state.scenario_type.value}_simulation",
    }

    exercise = await toolkit.design_exercise(scenario_input)

    # LLM enhancement for exercise design
    user_prompt = (
        f"Scenario type: {state.scenario_type.value}\n"
        f"Exercise mode: {state.exercise_mode.value}\n"
        f"Scope: {exercise.scope.value}\n"
        f"Participants: {', '.join(exercise.participants)}\n"
        f"Duration: {exercise.duration_min} minutes\n"
        f"Injects planned: {exercise.injects_planned}"
    )

    llm_summary = f"Designed {exercise.name} with {exercise.injects_planned} injects."

    try:
        result = cast(
            ExerciseDesignOutput,
            await llm_structured(
                system_prompt=SYSTEM_DESIGN_EXERCISE,
                user_prompt=user_prompt,
                schema=ExerciseDesignOutput,
            ),
        )
        llm_summary = (
            f"LLM-enhanced design: {result.name} "
            f"({result.injects_planned} injects, "
            f"{result.duration_min}min). "
            f"Objectives: {'; '.join(result.objectives[:3])}"
        )
    except Exception as e:
        logger.error("llm_design_exercise_failed", error=str(e))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    reasoning = f"[design_scenario] {llm_summary} ({elapsed}ms)"

    return {
        "exercise": exercise,
        "stage": SimStage.DESIGN_SCENARIO,
        "reasoning_chain": [*state.reasoning_chain, reasoning],
    }


async def inject_events(
    state: IncidentSimulatorState,
) -> dict[str, Any]:
    """Create and inject scenario events."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    if state.exercise is None:
        return {
            "error": "No exercise designed — skipping inject.",
            "stage": SimStage.INJECT_EVENTS,
        }

    injects = await toolkit.create_injects(state.exercise)

    # LLM enhancement for inject descriptions
    inject_lines = [
        f"- {inj.title} (severity={inj.severity}, target={inj.target_role})" for inj in injects
    ]
    user_prompt = (
        f"Exercise: {state.exercise.name}\n"
        f"Scenario: {state.scenario_type.value}\n"
        f"Injects:\n" + "\n".join(inject_lines)
    )

    llm_summary = f"Injected {len(injects)} events."

    try:
        result = cast(
            ScenarioOutput,
            await llm_structured(
                system_prompt=SYSTEM_INJECT_SCENARIO,
                user_prompt=user_prompt,
                schema=ScenarioOutput,
            ),
        )
        llm_summary = (
            f"LLM inject context: {result.title} "
            f"(severity={result.severity}, "
            f"target={result.target_role})"
        )
    except Exception as e:
        logger.error("llm_inject_scenario_failed", error=str(e))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    reasoning = f"[inject_events] {llm_summary} ({elapsed}ms)"

    return {
        "injects": injects,
        "stage": SimStage.INJECT_EVENTS,
        "reasoning_chain": [*state.reasoning_chain, reasoning],
    }


async def observe_response(
    state: IncidentSimulatorState,
) -> dict[str, Any]:
    """Observe team responses to injected events."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    if not state.injects:
        return {
            "error": "No injects to observe.",
            "stage": SimStage.OBSERVE_RESPONSE,
        }

    observations = await toolkit.observe_responses(state.injects)

    # LLM enhancement for observation analysis
    obs_lines = [
        f"- inject={o.inject_id}: "
        f"response_time={o.response_time_sec:.0f}s, "
        f"comm={o.communication_quality}, "
        f"decision={o.decision_quality}"
        for o in observations
    ]
    user_prompt = (
        f"Exercise: {state.exercise.name if state.exercise else 'unknown'}\n"
        f"Observations:\n" + "\n".join(obs_lines)
    )

    llm_summary = f"Observed {len(observations)} responses."

    try:
        result = cast(
            ObservationOutput,
            await llm_structured(
                system_prompt=SYSTEM_OBSERVE,
                user_prompt=user_prompt,
                schema=ObservationOutput,
            ),
        )
        llm_summary = (
            f"LLM observation: comm={result.communication_quality}, "
            f"decision={result.decision_quality}. "
            f"{result.notes[:100]}"
        )
    except Exception as e:
        logger.error("llm_observe_response_failed", error=str(e))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    reasoning = f"[observe_response] {llm_summary} ({elapsed}ms)"

    return {
        "observations": observations,
        "stage": SimStage.OBSERVE_RESPONSE,
        "reasoning_chain": [*state.reasoning_chain, reasoning],
    }


async def score_performance(
    state: IncidentSimulatorState,
) -> dict[str, Any]:
    """Measure and score team performance."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    measurements = await toolkit.measure_performance(state.observations)
    readiness = await toolkit.score_readiness(measurements, state.observations)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    reasoning = (
        f"[score_performance] Readiness={readiness.overall_score:.0f}% "
        f"grade={readiness.grade}, "
        f"{len(measurements)} metrics measured ({elapsed}ms)"
    )

    return {
        "measurements": measurements,
        "readiness": readiness,
        "readiness_score": readiness.overall_score,
        "stage": SimStage.SCORE_PERFORMANCE,
        "reasoning_chain": [*state.reasoning_chain, reasoning],
    }


async def debrief(
    state: IncidentSimulatorState,
) -> dict[str, Any]:
    """Generate readiness assessment using LLM."""
    start = datetime.now(UTC)

    # Build context for the LLM
    measurement_lines = [
        f"- {m.metric.value}: {m.value:.1f} {m.unit} "
        f"(target={m.target:.1f}, "
        f"{'MET' if m.met_target else 'MISSED'})"
        for m in state.measurements
    ]
    gap_lines = state.readiness.gaps if state.readiness else []
    strength_lines = state.readiness.strengths if state.readiness else []

    user_prompt = (
        f"Scenario: {state.scenario_type.value}\n"
        f"Mode: {state.exercise_mode.value}\n"
        f"Overall score: {state.readiness_score:.0f}%\n"
        f"Measurements:\n"
        + "\n".join(measurement_lines)
        + "\nStrengths:\n"
        + "\n".join(f"- {s}" for s in strength_lines)
        + "\nGaps:\n"
        + "\n".join(f"- {g}" for g in gap_lines)
    )

    llm_summary = f"Debrief completed. Score={state.readiness_score:.0f}%"
    try:
        result = cast(
            ReadinessOutput,
            await llm_structured(
                system_prompt=SYSTEM_SCORE_READINESS,
                user_prompt=user_prompt,
                schema=ReadinessOutput,
            ),
        )
        llm_summary = (
            f"LLM debrief: score={result.overall_score:.0f}, "
            f"grade={result.grade}. "
            f"Strengths: {len(result.strengths)}, "
            f"gaps: {len(result.gaps)}"
        )
        _ = result.recommendations  # available for future use
    except Exception as e:
        logger.error("llm_debrief_failed", error=str(e))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    reasoning = f"[debrief] {llm_summary} ({elapsed}ms)"

    return {
        "stage": SimStage.DEBRIEF,
        "reasoning_chain": [*state.reasoning_chain, reasoning],
    }


async def report(
    state: IncidentSimulatorState,
) -> dict[str, Any]:
    """Generate final simulation report using LLM."""
    start = datetime.now(UTC)

    exercise_name = state.exercise.name if state.exercise else "unknown"
    readiness_grade = state.readiness.grade if state.readiness else "N/A"

    context_lines = [
        f"Exercise: {exercise_name}",
        f"Scenario: {state.scenario_type.value}",
        f"Mode: {state.exercise_mode.value}",
        f"Readiness score: {state.readiness_score:.0f}%",
        f"Grade: {readiness_grade}",
        f"Injects delivered: {len(state.injects)}",
        f"Observations: {len(state.observations)}",
        "",
        "Reasoning chain:",
        *[f"  {r}" for r in state.reasoning_chain],
    ]
    user_prompt = "\n".join(context_lines)

    report_summary = (
        f"Incident simulation '{exercise_name}' completed. "
        f"Readiness: {state.readiness_score:.0f}% "
        f"(grade {readiness_grade})."
    )

    try:
        result = cast(
            ReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=user_prompt,
                schema=ReportOutput,
            ),
        )
        report_summary = (
            f"{result.executive_summary}\n\n"
            f"Exercises: {result.exercises_completed}. "
            f"Readiness: {result.overall_readiness}.\n"
            f"Findings: {'; '.join(result.key_findings[:3])}\n"
            f"Actions: {'; '.join(result.action_items[:3])}"
        )
    except Exception as e:
        logger.error("llm_report_failed", error=str(e))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    total_duration = (
        sum(int(r.split("(")[-1].rstrip("ms)")) for r in state.reasoning_chain if r.endswith("ms)"))
        + elapsed
    )

    reasoning = f"[report] Generated final report ({elapsed}ms)"

    return {
        "report_summary": report_summary,
        "stage": SimStage.REPORT,
        "duration_ms": total_duration,
        "reasoning_chain": [*state.reasoning_chain, reasoning],
    }
