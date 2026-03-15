"""Learning Feedback Loop Engine —
track agent learning feedback loops, evaluate feedback quality,
and optimize exploration rates for continuous improvement."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class FeedbackType(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"
    CORRECTIVE = "corrective"


class LearningPhase(StrEnum):
    EXPLORATION = "exploration"
    EXPLOITATION = "exploitation"
    EVALUATION = "evaluation"


class ConvergenceStatus(StrEnum):
    CONVERGING = "converging"
    DIVERGING = "diverging"
    OSCILLATING = "oscillating"
    CONVERGED = "converged"


# --- Models ---


class LearningFeedbackRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    model_id: str = ""
    feedback_type: FeedbackType = FeedbackType.NEUTRAL
    learning_phase: LearningPhase = LearningPhase.EXPLORATION
    convergence_status: ConvergenceStatus = ConvergenceStatus.DIVERGING
    feedback_score: float = 0.0
    exploration_rate: float = 0.0
    accuracy_delta: float = 0.0
    iteration_count: int = 0
    reward_signal: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class LearningFeedbackAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    learning_phase: LearningPhase = LearningPhase.EXPLORATION
    convergence_status: ConvergenceStatus = ConvergenceStatus.DIVERGING
    learning_efficiency: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class LearningFeedbackReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_feedback_score: float = 0.0
    by_feedback_type: dict[str, int] = Field(default_factory=dict)
    by_learning_phase: dict[str, int] = Field(default_factory=dict)
    by_convergence_status: dict[str, int] = Field(default_factory=dict)
    diverging_agents: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class LearningFeedbackLoopEngine:
    """Track agent learning feedback loops, evaluate feedback quality,
    and optimize exploration rates for continuous improvement."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[LearningFeedbackRecord] = []
        self._analyses: dict[str, LearningFeedbackAnalysis] = {}
        logger.info(
            "learning_feedback_loop_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        agent_id: str = "",
        model_id: str = "",
        feedback_type: FeedbackType = FeedbackType.NEUTRAL,
        learning_phase: LearningPhase = LearningPhase.EXPLORATION,
        convergence_status: ConvergenceStatus = ConvergenceStatus.DIVERGING,
        feedback_score: float = 0.0,
        exploration_rate: float = 0.0,
        accuracy_delta: float = 0.0,
        iteration_count: int = 0,
        reward_signal: float = 0.0,
        description: str = "",
    ) -> LearningFeedbackRecord:
        record = LearningFeedbackRecord(
            agent_id=agent_id,
            model_id=model_id,
            feedback_type=feedback_type,
            learning_phase=learning_phase,
            convergence_status=convergence_status,
            feedback_score=feedback_score,
            exploration_rate=exploration_rate,
            accuracy_delta=accuracy_delta,
            iteration_count=iteration_count,
            reward_signal=reward_signal,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "learning_feedback_loop.record_added",
            record_id=record.id,
            agent_id=agent_id,
        )
        return record

    def process(self, key: str) -> LearningFeedbackAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        convergence_weight = {
            ConvergenceStatus.CONVERGED: 1.0,
            ConvergenceStatus.CONVERGING: 0.7,
            ConvergenceStatus.OSCILLATING: 0.3,
            ConvergenceStatus.DIVERGING: 0.1,
        }
        efficiency = round(
            rec.feedback_score * 0.5
            + convergence_weight.get(rec.convergence_status, 0.0) * 0.3
            + max(rec.accuracy_delta, 0.0) * 0.2,
            4,
        )
        analysis = LearningFeedbackAnalysis(
            agent_id=rec.agent_id,
            learning_phase=rec.learning_phase,
            convergence_status=rec.convergence_status,
            learning_efficiency=efficiency,
            description=(
                f"Agent {rec.agent_id} -> efficiency={efficiency} "
                f"convergence={rec.convergence_status.value}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> LearningFeedbackReport:
        by_type: dict[str, int] = {}
        by_phase: dict[str, int] = {}
        by_conv: dict[str, int] = {}
        scores: list[float] = []
        for r in self._records:
            by_type[r.feedback_type.value] = by_type.get(r.feedback_type.value, 0) + 1
            by_phase[r.learning_phase.value] = by_phase.get(r.learning_phase.value, 0) + 1
            by_conv[r.convergence_status.value] = by_conv.get(r.convergence_status.value, 0) + 1
            scores.append(r.feedback_score)
        avg_score = round(sum(scores) / len(scores), 4) if scores else 0.0
        diverging = list(
            {
                r.agent_id
                for r in self._records
                if r.convergence_status
                in (ConvergenceStatus.DIVERGING, ConvergenceStatus.OSCILLATING)
                and r.agent_id
            }
        )[:10]
        recs: list[str] = []
        if diverging:
            recs.append(f"{len(diverging)} agents have diverging/oscillating learning")
        if avg_score < 0.5:
            recs.append("Average feedback score is below 0.5")
        if not recs:
            recs.append("Learning feedback loops operating within normal parameters")
        return LearningFeedbackReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_feedback_score=avg_score,
            by_feedback_type=by_type,
            by_learning_phase=by_phase,
            by_convergence_status=by_conv,
            diverging_agents=diverging,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            type_dist[r.feedback_type.value] = type_dist.get(r.feedback_type.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "feedback_type_distribution": type_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("learning_feedback_loop_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def track_learning_progress(self) -> list[dict[str, Any]]:
        """Track learning progress per agent over iterations."""
        agent_data: dict[str, list[LearningFeedbackRecord]] = {}
        for r in self._records:
            if r.agent_id:
                agent_data.setdefault(r.agent_id, []).append(r)
        results: list[dict[str, Any]] = []
        for agent_id, recs in agent_data.items():
            sorted_recs = sorted(recs, key=lambda x: x.created_at)
            total_iterations = sum(r.iteration_count for r in recs)
            avg_accuracy_delta = round(sum(r.accuracy_delta for r in recs) / len(recs), 4)
            avg_reward = round(sum(r.reward_signal for r in recs) / len(recs), 4)
            phases = list({r.learning_phase.value for r in recs})
            latest_convergence = sorted_recs[-1].convergence_status.value
            trend = (
                "improving"
                if avg_accuracy_delta > 0.01
                else "stable"
                if avg_accuracy_delta >= -0.01
                else "declining"
            )
            results.append(
                {
                    "agent_id": agent_id,
                    "total_iterations": total_iterations,
                    "avg_accuracy_delta": avg_accuracy_delta,
                    "avg_reward_signal": avg_reward,
                    "learning_phases": phases,
                    "latest_convergence": latest_convergence,
                    "trend": trend,
                    "record_count": len(recs),
                }
            )
        results.sort(key=lambda x: x["avg_accuracy_delta"], reverse=True)
        return results

    def evaluate_feedback_quality(self) -> list[dict[str, Any]]:
        """Evaluate quality of feedback by type and its impact on learning."""
        type_data: dict[str, list[LearningFeedbackRecord]] = {}
        for r in self._records:
            type_data.setdefault(r.feedback_type.value, []).append(r)
        results: list[dict[str, Any]] = []
        for fb_type, recs in type_data.items():
            avg_score = round(sum(r.feedback_score for r in recs) / len(recs), 4)
            avg_accuracy = round(sum(r.accuracy_delta for r in recs) / len(recs), 4)
            avg_reward = round(sum(r.reward_signal for r in recs) / len(recs), 4)
            converged_count = sum(
                1
                for r in recs
                if r.convergence_status
                in (ConvergenceStatus.CONVERGED, ConvergenceStatus.CONVERGING)
            )
            convergence_rate = round(converged_count / len(recs), 4)
            results.append(
                {
                    "feedback_type": fb_type,
                    "avg_feedback_score": avg_score,
                    "avg_accuracy_delta": avg_accuracy,
                    "avg_reward_signal": avg_reward,
                    "convergence_rate": convergence_rate,
                    "record_count": len(recs),
                    "quality_rating": (
                        "high"
                        if avg_score >= 0.7 and convergence_rate >= 0.6
                        else "medium"
                        if avg_score >= 0.4
                        else "low"
                    ),
                }
            )
        results.sort(key=lambda x: x["avg_feedback_score"], reverse=True)
        return results

    def optimize_exploration_rate(self) -> list[dict[str, Any]]:
        """Recommend optimal exploration rates per agent based on convergence."""
        agent_data: dict[str, list[LearningFeedbackRecord]] = {}
        for r in self._records:
            if r.agent_id:
                agent_data.setdefault(r.agent_id, []).append(r)
        results: list[dict[str, Any]] = []
        for agent_id, recs in agent_data.items():
            current_rate = round(sum(r.exploration_rate for r in recs) / len(recs), 4)
            avg_accuracy = round(sum(r.accuracy_delta for r in recs) / len(recs), 4)
            latest = sorted(recs, key=lambda x: x.created_at)[-1]
            convergence = latest.convergence_status
            if convergence == ConvergenceStatus.CONVERGED:
                optimal_rate = max(current_rate * 0.5, 0.01)
                reason = "Converged — reduce exploration"
            elif convergence == ConvergenceStatus.CONVERGING:
                optimal_rate = max(current_rate * 0.8, 0.05)
                reason = "Converging — gradually reduce exploration"
            elif convergence == ConvergenceStatus.OSCILLATING:
                optimal_rate = current_rate * 0.6
                reason = "Oscillating — stabilize with lower exploration"
            else:
                optimal_rate = min(current_rate * 1.5, 1.0)
                reason = "Diverging — increase exploration"
            results.append(
                {
                    "agent_id": agent_id,
                    "current_exploration_rate": current_rate,
                    "optimal_exploration_rate": round(optimal_rate, 4),
                    "convergence_status": convergence.value,
                    "avg_accuracy_delta": avg_accuracy,
                    "reason": reason,
                    "record_count": len(recs),
                }
            )
        results.sort(key=lambda x: x["current_exploration_rate"], reverse=True)
        return results
