"""Tool functions for the Reflection Engine Agent."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.reflection_engine.models import (
    AgentAction,
    ImprovementRecommendation,
    ImprovementType,
    LearningApplication,
    MistakeIdentification,
    OutcomeAssessment,
    OutcomeEvaluation,
)

logger = structlog.get_logger()


class ReflectionEngineToolkit:
    """Toolkit for reflection engine agent operations.

    Bridges the reflection agent to action stores, agent
    registries, and configuration backends for reading past
    actions and applying learned improvements.
    """

    def __init__(
        self,
        action_store: Any | None = None,
        agent_registry: Any | None = None,
        config_backend: Any | None = None,
        metrics_backend: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._action_store = action_store
        self._agent_registry = agent_registry
        self._config_backend = config_backend
        self._metrics_backend = metrics_backend
        self._policy_engine = policy_engine
        self._repository = repository

    async def collect_recent_actions(
        self,
        agent_id: str,
        time_range_hours: int = 24,
    ) -> list[AgentAction]:
        """Gather recent agent actions from the action store.

        Args:
            agent_id: ID of the agent to review. Use '*' for
                all agents (cross-agent reflection).
            time_range_hours: Number of hours to look back.

        Returns:
            List of agent actions within the time range.
        """
        logger.info(
            "reflection_engine.collect_recent_actions",
            agent_id=agent_id,
            time_range_hours=time_range_hours,
        )
        if self._action_store is not None:
            try:
                return await self._action_store.query(
                    agent_id=agent_id,
                    hours=time_range_hours,
                )
            except Exception:
                logger.warning("reflection_engine.action_store_fallback")
        return []

    async def evaluate_outcome(
        self,
        action: AgentAction,
        actual_result: str,
    ) -> OutcomeEvaluation:
        """Assess whether an action achieved its intended goal.

        Compares expected vs actual result, checks for false
        positives, and measures time-to-resolution.

        Args:
            action: The agent action to evaluate.
            actual_result: What actually happened after the
                action was taken.

        Returns:
            OutcomeEvaluation with assessment and scoring.
        """
        logger.info(
            "reflection_engine.evaluate_outcome",
            action_id=action.id,
            agent_id=action.agent_id,
        )

        # Heuristic pre-assessment before LLM enrichment
        assessment = OutcomeAssessment.UNKNOWN
        score = 0.5
        false_positive = False

        if actual_result and action.expected_result:
            expected_lower = action.expected_result.lower()
            actual_lower = actual_result.lower()

            if "resolved" in actual_lower:
                assessment = OutcomeAssessment.EFFECTIVE
                score = 0.85
            elif "partial" in actual_lower:
                assessment = OutcomeAssessment.PARTIALLY_EFFECTIVE
                score = 0.55
            elif "false_positive" in actual_lower or "benign" in actual_lower:
                assessment = OutcomeAssessment.INEFFECTIVE
                score = 0.15
                false_positive = True
            elif "worse" in actual_lower or "escalated" in actual_lower:
                assessment = OutcomeAssessment.COUNTERPRODUCTIVE
                score = 0.05

            # Boost score if expected matches actual
            if expected_lower in actual_lower:
                score = min(score + 0.1, 1.0)

        return OutcomeEvaluation(
            action_id=action.id,
            assessment=assessment,
            effectiveness_score=score,
            time_to_resolution_ms=action.duration_ms,
            false_positive=false_positive,
            reasoning=(f"Heuristic: expected='{action.expected_result}' actual='{actual_result}'"),
        )

    async def identify_mistakes(
        self,
        evaluations: list[OutcomeEvaluation],
    ) -> list[MistakeIdentification]:
        """Find patterns in ineffective or counterproductive actions.

        Groups evaluations by failure mode and identifies
        recurring patterns that indicate systemic issues.

        Args:
            evaluations: List of outcome evaluations to analyze.

        Returns:
            List of identified mistake patterns.
        """
        logger.info(
            "reflection_engine.identify_mistakes",
            evaluation_count=len(evaluations),
        )

        # Filter to non-effective evaluations
        failures = [
            e
            for e in evaluations
            if e.assessment
            in (
                OutcomeAssessment.INEFFECTIVE,
                OutcomeAssessment.COUNTERPRODUCTIVE,
                OutcomeAssessment.PARTIALLY_EFFECTIVE,
            )
        ]

        if not failures:
            return []

        mistakes: list[MistakeIdentification] = []

        # Pattern: false positives
        fp_evals = [e for e in failures if e.false_positive]
        if len(fp_evals) >= 2:
            mistakes.append(
                MistakeIdentification(
                    id=f"mist-{uuid4().hex[:8]}",
                    pattern_name="recurring_false_positives",
                    action_ids=[e.action_id for e in fp_evals],
                    frequency=len(fp_evals),
                    severity=("high" if len(fp_evals) >= 5 else "medium"),
                    root_cause=("Detection rules triggering on benign activity patterns"),
                    description=(
                        f"{len(fp_evals)} false positive actions detected in review period"
                    ),
                )
            )

        # Pattern: counterproductive actions
        cp_evals = [e for e in failures if e.assessment == OutcomeAssessment.COUNTERPRODUCTIVE]
        if cp_evals:
            mistakes.append(
                MistakeIdentification(
                    id=f"mist-{uuid4().hex[:8]}",
                    pattern_name="counterproductive_actions",
                    action_ids=[e.action_id for e in cp_evals],
                    frequency=len(cp_evals),
                    severity="critical",
                    root_cause=(
                        "Actions made situation worse — "
                        "review playbook logic and "
                        "confidence thresholds"
                    ),
                    description=(f"{len(cp_evals)} actions were counterproductive"),
                )
            )

        # Pattern: low effectiveness scores
        low_scores = [e for e in failures if e.effectiveness_score < 0.3]
        if len(low_scores) >= 3:
            mistakes.append(
                MistakeIdentification(
                    id=f"mist-{uuid4().hex[:8]}",
                    pattern_name="low_effectiveness_cluster",
                    action_ids=[e.action_id for e in low_scores],
                    frequency=len(low_scores),
                    severity="high",
                    root_cause=(
                        "Multiple actions with very low "
                        "effectiveness — systemic issue "
                        "in decision-making"
                    ),
                    description=(f"{len(low_scores)} actions scored below 0.3 effectiveness"),
                )
            )

        return mistakes

    async def generate_improvement(
        self,
        mistake: MistakeIdentification,
    ) -> ImprovementRecommendation:
        """Create an actionable improvement for a mistake pattern.

        Maps mistake patterns to specific improvement types
        and generates concrete recommendations with current
        vs recommended values.

        Args:
            mistake: The identified mistake pattern.

        Returns:
            An improvement recommendation.
        """
        logger.info(
            "reflection_engine.generate_improvement",
            mistake_id=mistake.id,
            pattern=mistake.pattern_name,
        )

        # Map pattern to improvement type
        type_map: dict[str, ImprovementType] = {
            "recurring_false_positives": (ImprovementType.FALSE_POSITIVE_SUPPRESS),
            "counterproductive_actions": (ImprovementType.PLAYBOOK_UPDATE),
            "low_effectiveness_cluster": (ImprovementType.THRESHOLD_ADJUST),
        }
        imp_type = type_map.get(
            mistake.pattern_name,
            ImprovementType.THRESHOLD_ADJUST,
        )

        # Priority from severity
        sev_priority = {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
        }
        priority = sev_priority.get(mistake.severity, 3)

        auto_applicable = (
            imp_type == ImprovementType.THRESHOLD_ADJUST and mistake.severity != "critical"
        )

        return ImprovementRecommendation(
            id=f"imp-{uuid4().hex[:8]}",
            mistake_id=mistake.id,
            improvement_type=imp_type,
            title=(f"Fix {mistake.pattern_name} ({mistake.frequency} occurrences)"),
            description=(
                f"Root cause: {mistake.root_cause}. "
                f"Recommendation based on {mistake.frequency}"
                f" observed failures."
            ),
            current_value="current_threshold",
            recommended_value="adjusted_threshold",
            estimated_impact=(
                f"Reduce {mistake.pattern_name} by ~{min(mistake.frequency * 15, 80)}%"
            ),
            auto_applicable=auto_applicable,
            priority=priority,
        )

    async def apply_learning(
        self,
        improvement: ImprovementRecommendation,
    ) -> LearningApplication:
        """Apply an improvement to agent configuration.

        Only auto-applies changes that are flagged as safe.
        High-risk changes are recorded but require human
        approval before application.

        Args:
            improvement: The improvement to apply.

        Returns:
            LearningApplication record of what was done.
        """
        logger.info(
            "reflection_engine.apply_learning",
            improvement_id=improvement.id,
            auto_applicable=improvement.auto_applicable,
        )

        if not improvement.auto_applicable:
            return LearningApplication(
                improvement_id=improvement.id,
                applied=False,
                change_description=("Requires human approval: " + improvement.title),
                rollback_info="N/A — not applied",
                validation_result="pending_human_review",
            )

        # Auto-apply safe changes via config backend
        applied = False
        if self._config_backend is not None:
            try:
                await self._config_backend.apply(improvement.model_dump())
                applied = True
            except Exception:
                logger.warning(
                    "reflection_engine.apply_fallback",
                    improvement_id=improvement.id,
                )

        return LearningApplication(
            improvement_id=improvement.id,
            applied=applied,
            applied_to_agent=improvement.mistake_id,
            change_description=(
                f"Applied: {improvement.title} — "
                f"{improvement.current_value} -> "
                f"{improvement.recommended_value}"
            ),
            rollback_info=(f"Revert to: {improvement.current_value}"),
            validation_result=("applied_successfully" if applied else "simulated_only"),
        )
