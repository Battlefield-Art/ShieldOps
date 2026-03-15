"""Optimization Convergence Detector Engine —
test convergence, distinguish local from global optima,
and recommend escape strategies."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ConvergenceType(StrEnum):
    GLOBAL_OPTIMUM = "global_optimum"
    LOCAL_OPTIMUM = "local_optimum"
    SADDLE_POINT = "saddle_point"
    NOT_CONVERGED = "not_converged"


class ConvergenceTest(StrEnum):
    GRADIENT_NORM = "gradient_norm"
    IMPROVEMENT_RATE = "improvement_rate"
    PARAMETER_STABILITY = "parameter_stability"
    ENSEMBLE_AGREEMENT = "ensemble_agreement"


class EscapeStrategy(StrEnum):
    PERTURBATION = "perturbation"
    RESTART = "restart"
    WIDER_SEARCH = "wider_search"
    ACCEPT_CONVERGENCE = "accept_convergence"


# --- Models ---


class OptimizationConvergenceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    convergence_type: ConvergenceType = ConvergenceType.NOT_CONVERGED
    convergence_test: ConvergenceTest = ConvergenceTest.IMPROVEMENT_RATE
    escape_strategy: EscapeStrategy = EscapeStrategy.ACCEPT_CONVERGENCE
    metric_value: float = 0.0
    gradient_norm: float = 0.0
    improvement_rate: float = 0.0
    iteration: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OptimizationConvergenceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    convergence_type: ConvergenceType = ConvergenceType.NOT_CONVERGED
    recommended_escape: EscapeStrategy = EscapeStrategy.ACCEPT_CONVERGENCE
    is_converged: bool = False
    confidence: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OptimizationConvergenceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    by_convergence_type: dict[str, int] = Field(default_factory=dict)
    by_convergence_test: dict[str, int] = Field(default_factory=dict)
    by_escape_strategy: dict[str, int] = Field(default_factory=dict)
    converged_experiments: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class OptimizationConvergenceDetectorEngine:
    """Test convergence, distinguish local from global optima,
    and recommend escape strategies."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[OptimizationConvergenceRecord] = []
        self._analyses: dict[str, OptimizationConvergenceAnalysis] = {}
        logger.info(
            "optimization_convergence_detector.init",
            max_records=max_records,
        )

    def add_record(
        self,
        experiment_id: str = "",
        convergence_type: ConvergenceType = ConvergenceType.NOT_CONVERGED,
        convergence_test: ConvergenceTest = ConvergenceTest.IMPROVEMENT_RATE,
        escape_strategy: EscapeStrategy = EscapeStrategy.ACCEPT_CONVERGENCE,
        metric_value: float = 0.0,
        gradient_norm: float = 0.0,
        improvement_rate: float = 0.0,
        iteration: int = 0,
        description: str = "",
    ) -> OptimizationConvergenceRecord:
        record = OptimizationConvergenceRecord(
            experiment_id=experiment_id,
            convergence_type=convergence_type,
            convergence_test=convergence_test,
            escape_strategy=escape_strategy,
            metric_value=metric_value,
            gradient_norm=gradient_norm,
            improvement_rate=improvement_rate,
            iteration=iteration,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "optimization_convergence.record_added",
            record_id=record.id,
            experiment_id=experiment_id,
        )
        return record

    def process(self, key: str) -> OptimizationConvergenceAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        is_converged = rec.convergence_type in (
            ConvergenceType.GLOBAL_OPTIMUM,
            ConvergenceType.LOCAL_OPTIMUM,
        )
        confidence_map = {
            ConvergenceType.GLOBAL_OPTIMUM: 0.95,
            ConvergenceType.LOCAL_OPTIMUM: 0.75,
            ConvergenceType.SADDLE_POINT: 0.5,
            ConvergenceType.NOT_CONVERGED: 0.1,
        }
        confidence = confidence_map.get(rec.convergence_type, 0.5)
        if rec.gradient_norm < 0.001:
            confidence = min(1.0, confidence + 0.1)
        recommended = rec.escape_strategy
        if rec.convergence_type == ConvergenceType.LOCAL_OPTIMUM:
            recommended = EscapeStrategy.PERTURBATION
        elif rec.convergence_type == ConvergenceType.SADDLE_POINT:
            recommended = EscapeStrategy.WIDER_SEARCH
        analysis = OptimizationConvergenceAnalysis(
            experiment_id=rec.experiment_id,
            convergence_type=rec.convergence_type,
            recommended_escape=recommended,
            is_converged=is_converged,
            confidence=round(confidence, 4),
            description=f"Experiment {rec.experiment_id} convergence={rec.convergence_type.value}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> OptimizationConvergenceReport:
        by_ct: dict[str, int] = {}
        by_ctest: dict[str, int] = {}
        by_es: dict[str, int] = {}
        converged: list[str] = []
        for r in self._records:
            by_ct[r.convergence_type.value] = by_ct.get(r.convergence_type.value, 0) + 1
            by_ctest[r.convergence_test.value] = by_ctest.get(r.convergence_test.value, 0) + 1
            by_es[r.escape_strategy.value] = by_es.get(r.escape_strategy.value, 0) + 1
            if r.convergence_type == ConvergenceType.GLOBAL_OPTIMUM:
                if r.experiment_id not in converged:
                    converged.append(r.experiment_id)
        recs_list: list[str] = []
        local = by_ct.get("local_optimum", 0)
        if local > 0:
            recs_list.append(f"{local} local optima — apply perturbation or restart")
        saddle = by_ct.get("saddle_point", 0)
        if saddle > 0:
            recs_list.append(f"{saddle} saddle points — widen search space")
        if not recs_list:
            recs_list.append("Convergence detection is healthy")
        return OptimizationConvergenceReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            by_convergence_type=by_ct,
            by_convergence_test=by_ctest,
            by_escape_strategy=by_es,
            converged_experiments=converged[:10],
            recommendations=recs_list,
        )

    def get_stats(self) -> dict[str, Any]:
        ct_dist: dict[str, int] = {}
        for r in self._records:
            ct_dist[r.convergence_type.value] = ct_dist.get(r.convergence_type.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "convergence_type_distribution": ct_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("optimization_convergence_detector.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def test_convergence(self, experiment_id: str) -> dict[str, Any]:
        """Run convergence tests on the experiment's optimization history."""
        exp_recs = sorted(
            [r for r in self._records if r.experiment_id == experiment_id],
            key=lambda x: x.iteration,
        )
        if len(exp_recs) < 3:
            return {
                "experiment_id": experiment_id,
                "converged": False,
                "reason": "insufficient_data",
            }
        recent = exp_recs[-5:]
        vals = [r.metric_value for r in recent]
        val_range = max(vals) - min(vals)
        improvement_rates = [r.improvement_rate for r in recent]
        avg_improvement = sum(improvement_rates) / len(improvement_rates)
        grad_norms = [r.gradient_norm for r in recent]
        avg_grad = sum(grad_norms) / len(grad_norms)
        converged = val_range < 0.001 and avg_improvement < 0.0001 and avg_grad < 0.01
        return {
            "experiment_id": experiment_id,
            "converged": converged,
            "value_range": round(val_range, 6),
            "avg_improvement_rate": round(avg_improvement, 6),
            "avg_gradient_norm": round(avg_grad, 6),
            "iterations_checked": len(recent),
        }

    def distinguish_local_from_global(self) -> list[dict[str, Any]]:
        """Classify each experiment's convergence as local or global."""
        exp_data: dict[str, dict[str, Any]] = {}
        for r in self._records:
            eid = r.experiment_id
            if eid not in exp_data:
                exp_data[eid] = {"values": [], "types": []}
            exp_data[eid]["values"].append(r.metric_value)
            exp_data[eid]["types"].append(r.convergence_type.value)
        results: list[dict[str, Any]] = []
        for eid, data in exp_data.items():
            vals = data["values"]
            best = max(vals)
            avg_non_best = sum(v for v in vals if v < best) / max(
                len([v for v in vals if v < best]), 1
            )
            gap = best - avg_non_best
            local_count = data["types"].count("local_optimum")
            global_count = data["types"].count("global_optimum")
            likely_global = gap > 0.05 and global_count > local_count
            results.append(
                {
                    "experiment_id": eid,
                    "best_value": round(best, 6),
                    "optimality_gap": round(gap, 6),
                    "likely_global": likely_global,
                    "local_convergence_count": local_count,
                    "global_convergence_count": global_count,
                }
            )
        results.sort(key=lambda x: x["optimality_gap"], reverse=True)
        return results

    def recommend_escape_strategy(self, experiment_id: str) -> dict[str, Any]:
        """Recommend an escape strategy for a stuck experiment."""
        exp_recs = [r for r in self._records if r.experiment_id == experiment_id]
        if not exp_recs:
            return {"experiment_id": experiment_id, "strategy": None, "reason": "no_data"}
        latest = max(exp_recs, key=lambda x: x.iteration)
        strategy = EscapeStrategy.ACCEPT_CONVERGENCE
        rationale = "optimization has converged globally"
        if latest.convergence_type == ConvergenceType.LOCAL_OPTIMUM:
            strategy = EscapeStrategy.PERTURBATION
            rationale = "local optimum — small perturbation to escape"
        elif latest.convergence_type == ConvergenceType.SADDLE_POINT:
            strategy = EscapeStrategy.WIDER_SEARCH
            rationale = "saddle point — expand search space"
        elif latest.convergence_type == ConvergenceType.NOT_CONVERGED:
            strategy = EscapeStrategy.RESTART
            rationale = "not converging — restart with new initialization"
        return {
            "experiment_id": experiment_id,
            "recommended_strategy": strategy.value,
            "rationale": rationale,
            "current_convergence": latest.convergence_type.value,
            "current_iteration": latest.iteration,
            "gradient_norm": latest.gradient_norm,
        }
