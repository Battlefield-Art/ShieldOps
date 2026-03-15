"""Convergence Optimizer Engine —
optimize self-learning loop convergence, detect plateau,
adjust learning rate, recommend early stopping."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ConvergencePhase(StrEnum):
    WARMING_UP = "warming_up"
    IMPROVING = "improving"
    PLATEAU = "plateau"
    DIVERGING = "diverging"


class OptimizationAction(StrEnum):
    CONTINUE = "continue"
    ADJUST_RATE = "adjust_rate"
    EARLY_STOP = "early_stop"
    RESTART = "restart"


class LearningRateStrategy(StrEnum):
    CONSTANT = "constant"
    DECAY = "decay"
    ADAPTIVE = "adaptive"
    COSINE = "cosine"


# --- Models ---


class ConvergenceOptimizerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    loop_id: str = ""
    convergence_phase: ConvergencePhase = ConvergencePhase.WARMING_UP
    optimization_action: OptimizationAction = OptimizationAction.CONTINUE
    learning_rate_strategy: LearningRateStrategy = LearningRateStrategy.CONSTANT
    metric_value: float = 0.0
    metric_delta: float = 0.0
    iteration: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ConvergenceOptimizerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    loop_id: str = ""
    convergence_phase: ConvergencePhase = ConvergencePhase.WARMING_UP
    avg_delta: float = 0.0
    trend_direction: str = ""
    recommended_action: OptimizationAction = OptimizationAction.CONTINUE
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ConvergenceOptimizerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_metric_value: float = 0.0
    by_convergence_phase: dict[str, int] = Field(default_factory=dict)
    by_optimization_action: dict[str, int] = Field(default_factory=dict)
    by_learning_rate_strategy: dict[str, int] = Field(default_factory=dict)
    diverging_loops: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ConvergenceOptimizerEngine:
    """Optimize self-learning loop convergence — detect plateau,
    adjust learning rate, recommend early stopping."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ConvergenceOptimizerRecord] = []
        self._analyses: dict[str, ConvergenceOptimizerAnalysis] = {}
        logger.info(
            "convergence_optimizer_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        loop_id: str = "",
        convergence_phase: ConvergencePhase = ConvergencePhase.WARMING_UP,
        optimization_action: OptimizationAction = OptimizationAction.CONTINUE,
        learning_rate_strategy: LearningRateStrategy = LearningRateStrategy.CONSTANT,
        metric_value: float = 0.0,
        metric_delta: float = 0.0,
        iteration: int = 0,
        description: str = "",
    ) -> ConvergenceOptimizerRecord:
        record = ConvergenceOptimizerRecord(
            loop_id=loop_id,
            convergence_phase=convergence_phase,
            optimization_action=optimization_action,
            learning_rate_strategy=learning_rate_strategy,
            metric_value=metric_value,
            metric_delta=metric_delta,
            iteration=iteration,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "convergence_optimizer.record_added",
            record_id=record.id,
            loop_id=loop_id,
            iteration=iteration,
        )
        return record

    def process(self, key: str) -> ConvergenceOptimizerAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        loop_recs = sorted(
            [r for r in self._records if r.loop_id == rec.loop_id],
            key=lambda x: x.iteration,
        )
        deltas = [r.metric_delta for r in loop_recs]
        avg_delta = round(sum(deltas) / len(deltas), 6) if deltas else 0.0
        if avg_delta > 0.01:
            trend = "improving"
        elif avg_delta < -0.01:
            trend = "degrading"
        else:
            trend = "stable"
        # Determine recommended action
        if rec.convergence_phase == ConvergencePhase.DIVERGING:
            action = OptimizationAction.RESTART
        elif rec.convergence_phase == ConvergencePhase.PLATEAU:
            action = OptimizationAction.ADJUST_RATE
        elif avg_delta < 0.001 and len(loop_recs) > 10:
            action = OptimizationAction.EARLY_STOP
        else:
            action = OptimizationAction.CONTINUE
        analysis = ConvergenceOptimizerAnalysis(
            loop_id=rec.loop_id,
            convergence_phase=rec.convergence_phase,
            avg_delta=avg_delta,
            trend_direction=trend,
            recommended_action=action,
            description=(f"Loop {rec.loop_id} trend={trend} avg_delta={avg_delta:.6f}"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ConvergenceOptimizerReport:
        by_cp: dict[str, int] = {}
        by_oa: dict[str, int] = {}
        by_lrs: dict[str, int] = {}
        for r in self._records:
            by_cp[r.convergence_phase.value] = by_cp.get(r.convergence_phase.value, 0) + 1
            by_oa[r.optimization_action.value] = by_oa.get(r.optimization_action.value, 0) + 1
            by_lrs[r.learning_rate_strategy.value] = (
                by_lrs.get(r.learning_rate_strategy.value, 0) + 1
            )
        metrics = [r.metric_value for r in self._records]
        avg_metric = round(sum(metrics) / len(metrics), 4) if metrics else 0.0
        diverging = list(
            {r.loop_id for r in self._records if r.convergence_phase == ConvergencePhase.DIVERGING}
        )
        recs_list: list[str] = []
        div_count = by_cp.get("diverging", 0)
        if div_count > 0:
            recs_list.append(
                f"{div_count} diverging record(s) — consider restart or rate adjustment"
            )
        plateau_count = by_cp.get("plateau", 0)
        if plateau_count > 0:
            recs_list.append(f"{plateau_count} plateau record(s) — evaluate early stopping")
        if not recs_list:
            recs_list.append("Convergence optimization is healthy")
        return ConvergenceOptimizerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_metric_value=avg_metric,
            by_convergence_phase=by_cp,
            by_optimization_action=by_oa,
            by_learning_rate_strategy=by_lrs,
            diverging_loops=sorted(diverging),
            recommendations=recs_list,
        )

    def get_stats(self) -> dict[str, Any]:
        cp_dist: dict[str, int] = {}
        for r in self._records:
            cp_dist[r.convergence_phase.value] = cp_dist.get(r.convergence_phase.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "convergence_phase_distribution": cp_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("convergence_optimizer_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def detect_plateau(self, loop_id: str, window: int = 5) -> dict[str, Any]:
        """Detect when a loop has plateaued (delta < threshold for N iterations)."""
        loop_recs = sorted(
            [r for r in self._records if r.loop_id == loop_id],
            key=lambda x: x.iteration,
        )
        if len(loop_recs) < window:
            return {
                "loop_id": loop_id,
                "plateaued": False,
                "reason": "insufficient_data",
                "records_available": len(loop_recs),
                "window_required": window,
            }
        recent = loop_recs[-window:]
        deltas = [abs(r.metric_delta) for r in recent]
        max_delta = max(deltas)
        avg_delta = sum(deltas) / len(deltas)
        threshold = 0.001
        plateaued = max_delta < threshold
        return {
            "loop_id": loop_id,
            "plateaued": plateaued,
            "max_delta_in_window": round(max_delta, 6),
            "avg_delta_in_window": round(avg_delta, 6),
            "threshold": threshold,
            "window_size": window,
            "iterations_checked": len(recent),
        }

    def recommend_learning_rate(self, loop_id: str) -> dict[str, Any]:
        """Suggest learning rate adjustment based on convergence history."""
        loop_recs = sorted(
            [r for r in self._records if r.loop_id == loop_id],
            key=lambda x: x.iteration,
        )
        if not loop_recs:
            return {
                "loop_id": loop_id,
                "recommendation": None,
                "reason": "no_data",
            }
        deltas = [r.metric_delta for r in loop_recs]
        avg_delta = sum(deltas) / len(deltas)
        recent_deltas = deltas[-5:] if len(deltas) >= 5 else deltas
        avg_recent = sum(recent_deltas) / len(recent_deltas)
        # Determine current phase from latest record
        latest_phase = loop_recs[-1].convergence_phase
        if latest_phase == ConvergencePhase.DIVERGING:
            strategy = LearningRateStrategy.DECAY
            rationale = "diverging — reduce learning rate with decay schedule"
            multiplier = 0.5
        elif latest_phase == ConvergencePhase.PLATEAU:
            if avg_recent > 0:
                strategy = LearningRateStrategy.COSINE
                rationale = "plateau with positive trend — try cosine annealing"
                multiplier = 1.5
            else:
                strategy = LearningRateStrategy.ADAPTIVE
                rationale = "plateau with no improvement — switch to adaptive"
                multiplier = 2.0
        elif latest_phase == ConvergencePhase.WARMING_UP:
            strategy = LearningRateStrategy.CONSTANT
            rationale = "still warming up — maintain current rate"
            multiplier = 1.0
        else:
            strategy = LearningRateStrategy.ADAPTIVE
            rationale = "actively improving — use adaptive rate"
            multiplier = 1.0
        return {
            "loop_id": loop_id,
            "recommended_strategy": strategy.value,
            "rate_multiplier": multiplier,
            "rationale": rationale,
            "current_phase": latest_phase.value,
            "avg_delta": round(avg_delta, 6),
            "avg_recent_delta": round(avg_recent, 6),
            "total_iterations": len(loop_recs),
        }

    def estimate_remaining_iterations(self, loop_id: str, target_metric: float) -> dict[str, Any]:
        """Estimate how many more iterations to reach target metric."""
        loop_recs = sorted(
            [r for r in self._records if r.loop_id == loop_id],
            key=lambda x: x.iteration,
        )
        if len(loop_recs) < 2:
            return {
                "loop_id": loop_id,
                "target_metric": target_metric,
                "estimated_iterations": -1,
                "reason": "insufficient_data",
            }
        current_value = loop_recs[-1].metric_value
        if current_value >= target_metric:
            return {
                "loop_id": loop_id,
                "target_metric": target_metric,
                "current_value": round(current_value, 6),
                "estimated_iterations": 0,
                "reason": "target_already_reached",
            }
        # Average improvement per iteration
        deltas = [r.metric_delta for r in loop_recs if r.metric_delta > 0]
        if not deltas:
            return {
                "loop_id": loop_id,
                "target_metric": target_metric,
                "current_value": round(current_value, 6),
                "estimated_iterations": -1,
                "reason": "no_positive_deltas",
            }
        avg_positive_delta = sum(deltas) / len(deltas)
        remaining_gap = target_metric - current_value
        estimated = int(remaining_gap / avg_positive_delta) + 1
        return {
            "loop_id": loop_id,
            "target_metric": target_metric,
            "current_value": round(current_value, 6),
            "avg_improvement_per_iteration": round(avg_positive_delta, 6),
            "remaining_gap": round(remaining_gap, 6),
            "estimated_iterations": estimated,
        }
