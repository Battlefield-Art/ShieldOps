"""Node implementations for the Reflection Engine Agent LangGraph workflow."""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.reflection_engine.models import (
    ImprovementRecommendation,
    OutcomeAssessment,
    OutcomeEvaluation,
    ReasoningStep,
    ReflectionEngineState,
    ReflectionStage,
)
from shieldops.agents.reflection_engine.prompts import (
    SYSTEM_APPLY_LEARNING,
    SYSTEM_EVALUATE_OUTCOME,
    SYSTEM_GENERATE_IMPROVEMENT,
    SYSTEM_IDENTIFY_MISTAKES,
    SYSTEM_REPORT,
    ImprovementOutput,
    LearningApplicationOutput,
    MistakePatternOutput,
    OutcomeEvaluationOutput,
    ReflectionReportOutput,
)
from shieldops.agents.reflection_engine.tools import (
    ReflectionEngineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ReflectionEngineToolkit | None = None


def _get_toolkit() -> ReflectionEngineToolkit:
    if _toolkit is None:
        return ReflectionEngineToolkit()
    return _toolkit


async def collect_agent_actions(
    state: ReflectionEngineState,
) -> dict[str, Any]:
    """Collect recent actions from the target agent."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.collect_recent_actions(
        agent_id=state.agent_id,
        time_range_hours=state.time_range_hours,
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_agent_actions",
        input_summary=(f"agent={state.agent_id}, range={state.time_range_hours}h"),
        output_summary=(f"Collected {len(actions)} agent actions"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="collect_recent_actions",
    )

    return {
        "actions_reviewed": actions,
        "total_actions_reviewed": len(actions),
        "current_stage": ReflectionStage.COLLECT_ACTIONS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
    }


async def evaluate_outcomes(
    state: ReflectionEngineState,
) -> dict[str, Any]:
    """Evaluate each action's outcome using LLM reasoning."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    evaluations: list[OutcomeEvaluation] = []
    for action in state.actions_reviewed:
        # Get baseline heuristic evaluation
        base_eval = await toolkit.evaluate_outcome(
            action=action,
            actual_result=action.actual_result,
        )

        # Enrich with LLM counterfactual reasoning
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_EVALUATE_OUTCOME,
                user_prompt=(
                    f"Agent: {action.agent_id} "
                    f"({action.agent_type})\n"
                    f"Action: {action.action_type}\n"
                    f"Description: {action.description}\n"
                    f"Target: {action.target_entity}\n"
                    f"Confidence: {action.confidence:.2f}\n"
                    f"Expected: {action.expected_result}\n"
                    f"Actual: {action.actual_result}\n"
                    f"Duration: {action.duration_ms}ms"
                ),
                output_schema=OutcomeEvaluationOutput,
            )
            evaluations.append(
                OutcomeEvaluation(
                    action_id=action.id,
                    assessment=OutcomeAssessment(result.assessment),
                    effectiveness_score=(result.effectiveness_score),
                    time_to_resolution_ms=(action.duration_ms),
                    false_positive=result.false_positive,
                    collateral_impact=(result.collateral_impact),
                    counterfactual=result.counterfactual,
                    reasoning=result.reasoning,
                )
            )
        except Exception:
            logger.warning(
                "reflection_engine.llm_evaluate_fallback",
                action_id=action.id,
            )
            evaluations.append(base_eval)

    # Calculate aggregate effectiveness
    eff_score = 0.0
    if evaluations:
        eff_score = sum(e.effectiveness_score for e in evaluations) / len(evaluations)

    fp_count = sum(1 for e in evaluations if e.false_positive)
    fp_rate = fp_count / len(evaluations) if evaluations else 0.0

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="evaluate_outcomes",
        input_summary=(f"{len(state.actions_reviewed)} actions"),
        output_summary=(
            f"Evaluated {len(evaluations)} outcomes, "
            f"effectiveness={eff_score:.2f}, "
            f"FP rate={fp_rate:.2f}"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm_structured",
    )

    return {
        "evaluations": evaluations,
        "effectiveness_score": eff_score,
        "false_positive_rate": fp_rate,
        "current_stage": (ReflectionStage.EVALUATE_OUTCOMES),
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
    }


async def identify_mistakes(
    state: ReflectionEngineState,
) -> dict[str, Any]:
    """Identify patterns in ineffective actions via LLM."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # Get heuristic mistake patterns
    base_mistakes = await toolkit.identify_mistakes(state.evaluations)

    # Enrich with LLM cross-action pattern analysis
    failures = [
        e
        for e in state.evaluations
        if e.assessment
        in (
            OutcomeAssessment.INEFFECTIVE,
            OutcomeAssessment.COUNTERPRODUCTIVE,
            OutcomeAssessment.PARTIALLY_EFFECTIVE,
        )
    ]

    if failures:
        failure_summary = "\n".join(
            f"- [{e.assessment}] action={e.action_id} "
            f"score={e.effectiveness_score:.2f} "
            f"fp={e.false_positive} "
            f"reason={e.reasoning[:80]}"
            for e in failures
        )
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_IDENTIFY_MISTAKES,
                user_prompt=(
                    f"Total evaluations: "
                    f"{len(state.evaluations)}\n"
                    f"Failures: {len(failures)}\n"
                    f"False positives: "
                    f"{sum(1 for e in failures if e.false_positive)}\n"
                    f"\nFailed actions:\n{failure_summary}"
                ),
                output_schema=MistakePatternOutput,
            )
            # Merge LLM-identified patterns
            llm_pattern_names = {m.pattern_name for m in base_mistakes}
            if result.pattern_name not in llm_pattern_names:
                from uuid import uuid4

                from shieldops.agents.reflection_engine.models import (
                    MistakeIdentification,
                )

                base_mistakes.append(
                    MistakeIdentification(
                        id=f"mist-{uuid4().hex[:8]}",
                        pattern_name=result.pattern_name,
                        action_ids=(result.affected_action_ids),
                        frequency=len(result.affected_action_ids),
                        severity=result.severity,
                        root_cause=result.root_cause,
                        description=result.description,
                    )
                )
        except Exception:
            logger.warning(
                "reflection_engine.llm_mistakes_fallback",
            )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="identify_mistakes",
        input_summary=(f"{len(state.evaluations)} evaluations, {len(failures)} failures"),
        output_summary=(f"Found {len(base_mistakes)} mistake patterns"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm_structured",
    )

    return {
        "mistakes_found": base_mistakes,
        "total_mistakes_found": len(base_mistakes),
        "current_stage": (ReflectionStage.IDENTIFY_MISTAKES),
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
    }


async def generate_improvements(
    state: ReflectionEngineState,
) -> dict[str, Any]:
    """Generate improvement recommendations via LLM."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    improvements: list[ImprovementRecommendation] = []
    for mistake in state.mistakes_found:
        # Get baseline recommendation
        base_imp = await toolkit.generate_improvement(mistake)

        # Enrich with LLM reasoning
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_GENERATE_IMPROVEMENT,
                user_prompt=(
                    f"Mistake: {mistake.pattern_name}\n"
                    f"Severity: {mistake.severity}\n"
                    f"Frequency: {mistake.frequency}\n"
                    f"Root cause: {mistake.root_cause}\n"
                    f"Description: {mistake.description}\n"
                    f"Affected actions: "
                    f"{len(mistake.action_ids)}"
                ),
                output_schema=ImprovementOutput,
            )
            from shieldops.agents.reflection_engine.models import (
                ImprovementType,
            )

            improvements.append(
                ImprovementRecommendation(
                    id=base_imp.id,
                    mistake_id=mistake.id,
                    improvement_type=ImprovementType(result.improvement_type),
                    title=result.title,
                    description=result.description,
                    current_value=result.current_value,
                    recommended_value=(result.recommended_value),
                    estimated_impact=(result.estimated_impact),
                    auto_applicable=(result.auto_applicable),
                    priority=result.priority,
                )
            )
        except Exception:
            logger.warning(
                "reflection_engine.llm_improvement_fallback",
                mistake_id=mistake.id,
            )
            improvements.append(base_imp)

    # Sort by priority
    improvements.sort(key=lambda i: i.priority)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_improvements",
        input_summary=(f"{len(state.mistakes_found)} mistakes"),
        output_summary=(f"Generated {len(improvements)} improvements"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm_structured",
    )

    return {
        "improvements_recommended": improvements,
        "total_improvements": len(improvements),
        "current_stage": (ReflectionStage.GENERATE_IMPROVEMENTS),
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
    }


async def apply_learnings(
    state: ReflectionEngineState,
) -> dict[str, Any]:
    """Apply improvement recommendations with LLM validation."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    from shieldops.agents.reflection_engine.models import (
        LearningApplication,
    )

    applications: list[LearningApplication] = []
    for improvement in state.improvements_recommended:
        # LLM validates whether to apply
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_APPLY_LEARNING,
                user_prompt=(
                    f"Improvement: {improvement.title}\n"
                    f"Type: {improvement.improvement_type}\n"
                    f"Current: {improvement.current_value}\n"
                    f"Recommended: "
                    f"{improvement.recommended_value}\n"
                    f"Auto-applicable: "
                    f"{improvement.auto_applicable}\n"
                    f"Priority: {improvement.priority}\n"
                    f"Impact: {improvement.estimated_impact}"
                ),
                output_schema=LearningApplicationOutput,
            )

            if result.should_apply:
                app = await toolkit.apply_learning(improvement)
                app.change_description = result.change_description
                app.rollback_info = result.rollback_info
                applications.append(app)
            else:
                applications.append(
                    LearningApplication(
                        improvement_id=improvement.id,
                        applied=False,
                        change_description=(f"LLM rejected: {result.risk_assessment}"),
                        rollback_info="N/A",
                        validation_result=("rejected_by_llm"),
                    )
                )
        except Exception:
            logger.warning(
                "reflection_engine.llm_apply_fallback",
                improvement_id=improvement.id,
            )
            app = await toolkit.apply_learning(improvement)
            applications.append(app)

    applied_count = sum(1 for a in applications if a.applied)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="apply_learnings",
        input_summary=(f"{len(state.improvements_recommended)} improvements"),
        output_summary=(f"Applied {applied_count}/{len(applications)} learnings"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm_structured",
    )

    return {
        "learnings_applied": applications,
        "total_learnings_applied": applied_count,
        "current_stage": ReflectionStage.APPLY_LEARNINGS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
    }


async def generate_report(
    state: ReflectionEngineState,
) -> dict[str, Any]:
    """Generate the final reflection report with LLM summary."""
    start = datetime.now(UTC)

    try:
        mistakes_summary = "\n".join(
            f"- [{m.severity}] {m.pattern_name}: {m.description}" for m in state.mistakes_found
        )
        improvements_summary = "\n".join(
            f"- [P{i.priority}] {i.title}" for i in state.improvements_recommended
        )
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(
                f"Agent: {state.agent_id}\n"
                f"Time range: {state.time_range_hours}h\n"
                f"Actions reviewed: "
                f"{state.total_actions_reviewed}\n"
                f"Effectiveness: "
                f"{state.effectiveness_score:.2f}\n"
                f"FP rate: "
                f"{state.false_positive_rate:.2f}\n"
                f"Mistakes: "
                f"{state.total_mistakes_found}\n"
                f"Improvements: "
                f"{state.total_improvements}\n"
                f"Learnings applied: "
                f"{state.total_learnings_applied}\n"
                f"\nMistake patterns:\n"
                f"{mistakes_summary}\n"
                f"\nImprovement recommendations:\n"
                f"{improvements_summary}"
            ),
            output_schema=ReflectionReportOutput,
        )
        report_summary = result.executive_summary
        eff = result.effectiveness_score
    except Exception:
        logger.warning("reflection_engine.llm_report_fallback")
        report_summary = (
            f"Reviewed {state.total_actions_reviewed} "
            f"actions for agent {state.agent_id}. "
            f"Effectiveness: "
            f"{state.effectiveness_score:.2f}. "
            f"Found {state.total_mistakes_found} "
            f"mistake patterns. "
            f"Generated {state.total_improvements} "
            f"improvements. "
            f"Applied {state.total_learnings_applied} "
            f"learnings."
        )
        eff = state.effectiveness_score

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=(
            f"{state.total_actions_reviewed} actions, {state.total_mistakes_found} mistakes"
        ),
        output_summary=report_summary[:120],
        duration_ms=elapsed,
        tool_used="llm_structured",
    )

    return {
        "effectiveness_score": eff,
        "current_stage": ReflectionStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "session_duration_ms": sum(s.duration_ms for s in state.reasoning_chain) + elapsed,
    }
