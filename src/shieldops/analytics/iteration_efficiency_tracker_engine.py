"""Iteration Efficiency Tracker Engine —
compute marginal improvement, detect diminishing returns,
and recommend early stopping."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EfficiencyTrend(StrEnum):
    ACCELERATING = "accelerating"
    STEADY = "steady"
    DIMINISHING = "diminishing"
    NEGATIVE = "negative"


class StoppingCriteria(StrEnum):
    CONVERGENCE = "convergence"
    BUDGET_EXHAUSTED = "budget_exhausted"
    PLATEAU_DETECTED = "plateau_detected"
    REGRESSION_DETECTED = "regression_detected"


class IterationType(StrEnum):
    FULL_EVALUATION = "full_evaluation"
    MINI_BATCH = "mini_batch"
    CHECKPOINT = "checkpoint"
    WARMUP = "warmup"


# --- Models ---


class IterationEfficiencyRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    efficiency_trend: EfficiencyTrend = EfficiencyTrend.STEADY
    stopping_criteria: StoppingCriteria = StoppingCriteria.CONVERGENCE
    iteration_type: IterationType = IterationType.FULL_EVALUATION
    iteration_number: int = 0
    metric_value: float = 0.0
    cost_per_iteration: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class IterationEfficiencyAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    marginal_improvement: float = 0.0
    efficiency_trend: EfficiencyTrend = EfficiencyTrend.STEADY
    should_stop: bool = False
    stopping_reason: str = ""
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class IterationEfficiencyReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    by_efficiency_trend: dict[str, int] = Field(default_factory=dict)
    by_stopping_criteria: dict[str, int] = Field(default_factory=dict)
    by_iteration_type: dict[str, int] = Field(default_factory=dict)
    top_efficient: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class IterationEfficiencyTrackerEngine:
    """Compute marginal improvement, detect diminishing returns,
    and recommend early stopping."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[IterationEfficiencyRecord] = []
        self._analyses: dict[str, IterationEfficiencyAnalysis] = {}
        logger.info(
            "iteration_efficiency_tracker.init",
            max_records=max_records,
        )

    def add_record(
        self,
        experiment_id: str = "",
        efficiency_trend: EfficiencyTrend = EfficiencyTrend.STEADY,
        stopping_criteria: StoppingCriteria = StoppingCriteria.CONVERGENCE,
        iteration_type: IterationType = IterationType.FULL_EVALUATION,
        iteration_number: int = 0,
        metric_value: float = 0.0,
        cost_per_iteration: float = 0.0,
        description: str = "",
    ) -> IterationEfficiencyRecord:
        record = IterationEfficiencyRecord(
            experiment_id=experiment_id,
            efficiency_trend=efficiency_trend,
            stopping_criteria=stopping_criteria,
            iteration_type=iteration_type,
            iteration_number=iteration_number,
            metric_value=metric_value,
            cost_per_iteration=cost_per_iteration,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "iteration_efficiency.record_added",
            record_id=record.id,
            experiment_id=experiment_id,
        )
        return record

    def process(self, key: str) -> IterationEfficiencyAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        exp_recs = sorted(
            [r for r in self._records if r.experiment_id == rec.experiment_id],
            key=lambda x: x.iteration_number,
        )
        marginal = 0.0
        if len(exp_recs) >= 2:
            prev_val = exp_recs[-2].metric_value
            curr_val = exp_recs[-1].metric_value
            marginal = round(curr_val - prev_val, 6)
        should_stop = rec.efficiency_trend in (
            EfficiencyTrend.NEGATIVE,
            EfficiencyTrend.DIMINISHING,
        )
        stopping_reason = rec.stopping_criteria.value if should_stop else ""
        analysis = IterationEfficiencyAnalysis(
            experiment_id=rec.experiment_id,
            marginal_improvement=marginal,
            efficiency_trend=rec.efficiency_trend,
            should_stop=should_stop,
            stopping_reason=stopping_reason,
            description=f"Experiment {rec.experiment_id} marginal={marginal}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> IterationEfficiencyReport:
        by_et: dict[str, int] = {}
        by_sc: dict[str, int] = {}
        by_it: dict[str, int] = {}
        for r in self._records:
            by_et[r.efficiency_trend.value] = by_et.get(r.efficiency_trend.value, 0) + 1
            by_sc[r.stopping_criteria.value] = by_sc.get(r.stopping_criteria.value, 0) + 1
            by_it[r.iteration_type.value] = by_it.get(r.iteration_type.value, 0) + 1
        exp_efficiency: dict[str, float] = {}
        for r in self._records:
            if r.cost_per_iteration > 0:
                ratio = r.metric_value / r.cost_per_iteration
                if r.experiment_id not in exp_efficiency or ratio > exp_efficiency[r.experiment_id]:
                    exp_efficiency[r.experiment_id] = ratio
        top_efficient = sorted(exp_efficiency, key=lambda x: exp_efficiency[x], reverse=True)[:10]
        recs_list: list[str] = []
        diminishing = by_et.get("diminishing", 0)
        if diminishing > 0:
            recs_list.append(f"{diminishing} experiments showing diminishing returns")
        negative = by_et.get("negative", 0)
        if negative > 0:
            recs_list.append(f"{negative} experiments with negative efficiency")
        if not recs_list:
            recs_list.append("Iteration efficiency is healthy")
        return IterationEfficiencyReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            by_efficiency_trend=by_et,
            by_stopping_criteria=by_sc,
            by_iteration_type=by_it,
            top_efficient=top_efficient,
            recommendations=recs_list,
        )

    def get_stats(self) -> dict[str, Any]:
        et_dist: dict[str, int] = {}
        for r in self._records:
            et_dist[r.efficiency_trend.value] = et_dist.get(r.efficiency_trend.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "efficiency_trend_distribution": et_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("iteration_efficiency_tracker.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def compute_marginal_improvement(self, experiment_id: str) -> list[dict[str, Any]]:
        """Compute per-iteration marginal improvement for an experiment."""
        exp_recs = sorted(
            [r for r in self._records if r.experiment_id == experiment_id],
            key=lambda x: x.iteration_number,
        )
        if len(exp_recs) < 2:
            return []
        results: list[dict[str, Any]] = []
        for i in range(1, len(exp_recs)):
            prev = exp_recs[i - 1]
            curr = exp_recs[i]
            delta = curr.metric_value - prev.metric_value
            cost_efficiency = (
                delta / curr.cost_per_iteration if curr.cost_per_iteration > 0 else 0.0
            )
            results.append(
                {
                    "iteration": curr.iteration_number,
                    "metric_value": curr.metric_value,
                    "marginal_improvement": round(delta, 6),
                    "cost_per_iteration": curr.cost_per_iteration,
                    "cost_efficiency": round(cost_efficiency, 6),
                    "iteration_type": curr.iteration_type.value,
                }
            )
        return results

    def detect_diminishing_returns(self) -> list[dict[str, Any]]:
        """Detect experiments with diminishing marginal returns."""
        exp_records: dict[str, list[IterationEfficiencyRecord]] = {}
        for r in self._records:
            exp_records.setdefault(r.experiment_id, []).append(r)
        results: list[dict[str, Any]] = []
        for eid, recs in exp_records.items():
            if len(recs) < 3:
                continue
            sorted_recs = sorted(recs, key=lambda x: x.iteration_number)
            deltas: list[float] = []
            for i in range(1, len(sorted_recs)):
                deltas.append(sorted_recs[i].metric_value - sorted_recs[i - 1].metric_value)
            if len(deltas) < 2:
                continue
            trend_declining = all(deltas[i] <= deltas[i - 1] for i in range(1, len(deltas)))
            avg_delta = sum(deltas) / len(deltas)
            results.append(
                {
                    "experiment_id": eid,
                    "diminishing_returns": trend_declining,
                    "avg_marginal_improvement": round(avg_delta, 6),
                    "latest_marginal": round(deltas[-1], 6),
                    "iterations_analyzed": len(deltas),
                }
            )
        results.sort(key=lambda x: x["avg_marginal_improvement"])
        return results

    def recommend_early_stopping(self) -> list[dict[str, Any]]:
        """Recommend which experiments should stop early."""
        exp_records: dict[str, list[IterationEfficiencyRecord]] = {}
        for r in self._records:
            exp_records.setdefault(r.experiment_id, []).append(r)
        results: list[dict[str, Any]] = []
        for eid, recs in exp_records.items():
            sorted_recs = sorted(recs, key=lambda x: x.iteration_number)
            latest = sorted_recs[-1]
            stop = False
            reason = "continue"
            if latest.efficiency_trend == EfficiencyTrend.NEGATIVE:
                stop = True
                reason = "regression_detected"
            elif latest.efficiency_trend == EfficiencyTrend.DIMINISHING and len(sorted_recs) > 5:
                stop = True
                reason = "diminishing_returns"
            elif latest.stopping_criteria == StoppingCriteria.BUDGET_EXHAUSTED:
                stop = True
                reason = "budget_exhausted"
            results.append(
                {
                    "experiment_id": eid,
                    "should_stop": stop,
                    "reason": reason,
                    "total_iterations": len(sorted_recs),
                    "latest_trend": latest.efficiency_trend.value,
                }
            )
        results.sort(key=lambda x: x["should_stop"], reverse=True)
        return results
