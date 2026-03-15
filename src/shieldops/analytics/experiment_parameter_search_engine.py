"""Experiment Parameter Search Engine —
select next parameters, compute sensitivity,
and estimate remaining search value."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SearchStrategy(StrEnum):
    GRID_SEARCH = "grid_search"
    RANDOM_SEARCH = "random_search"
    BAYESIAN = "bayesian"
    SUCCESSIVE_HALVING = "successive_halving"


class ParameterSensitivity(StrEnum):
    HIGH_IMPACT = "high_impact"
    MODERATE_IMPACT = "moderate_impact"
    LOW_IMPACT = "low_impact"
    NEGLIGIBLE = "negligible"


class SearchPhase(StrEnum):
    EXPLORATION = "exploration"
    EXPLOITATION = "exploitation"
    REFINEMENT = "refinement"
    VERIFICATION = "verification"


# --- Models ---


class ExperimentParameterRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    parameter_name: str = ""
    strategy: SearchStrategy = SearchStrategy.BAYESIAN
    sensitivity: ParameterSensitivity = ParameterSensitivity.HIGH_IMPACT
    phase: SearchPhase = SearchPhase.EXPLORATION
    parameter_value: float = 0.0
    outcome_score: float = 0.0
    search_iteration: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ExperimentParameterAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    best_parameter_value: float = 0.0
    best_outcome_score: float = 0.0
    current_phase: SearchPhase = SearchPhase.EXPLORATION
    estimated_remaining_value: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ExperimentParameterReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    by_strategy: dict[str, int] = Field(default_factory=dict)
    by_sensitivity: dict[str, int] = Field(default_factory=dict)
    by_phase: dict[str, int] = Field(default_factory=dict)
    top_experiments: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ExperimentParameterSearchEngine:
    """Select next parameters, compute sensitivity,
    and estimate remaining search value."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ExperimentParameterRecord] = []
        self._analyses: dict[str, ExperimentParameterAnalysis] = {}
        logger.info(
            "experiment_parameter_search.init",
            max_records=max_records,
        )

    def add_record(
        self,
        experiment_id: str = "",
        parameter_name: str = "",
        strategy: SearchStrategy = SearchStrategy.BAYESIAN,
        sensitivity: ParameterSensitivity = ParameterSensitivity.HIGH_IMPACT,
        phase: SearchPhase = SearchPhase.EXPLORATION,
        parameter_value: float = 0.0,
        outcome_score: float = 0.0,
        search_iteration: int = 0,
        description: str = "",
    ) -> ExperimentParameterRecord:
        record = ExperimentParameterRecord(
            experiment_id=experiment_id,
            parameter_name=parameter_name,
            strategy=strategy,
            sensitivity=sensitivity,
            phase=phase,
            parameter_value=parameter_value,
            outcome_score=outcome_score,
            search_iteration=search_iteration,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "experiment_parameter.record_added",
            record_id=record.id,
            experiment_id=experiment_id,
        )
        return record

    def process(self, key: str) -> ExperimentParameterAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        exp_recs = [r for r in self._records if r.experiment_id == rec.experiment_id]
        best_score = max((r.outcome_score for r in exp_recs), default=0.0)
        best_val = 0.0
        for r in exp_recs:
            if r.outcome_score == best_score:
                best_val = r.parameter_value
                break
        scores = [r.outcome_score for r in exp_recs]
        avg_score = sum(scores) / len(scores) if scores else 0.0
        remaining_value = round(max(0.0, best_score - avg_score), 6)
        analysis = ExperimentParameterAnalysis(
            experiment_id=rec.experiment_id,
            best_parameter_value=best_val,
            best_outcome_score=round(best_score, 6),
            current_phase=rec.phase,
            estimated_remaining_value=remaining_value,
            description=f"Experiment {rec.experiment_id} best={best_score:.4f}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ExperimentParameterReport:
        by_s: dict[str, int] = {}
        by_sens: dict[str, int] = {}
        by_p: dict[str, int] = {}
        for r in self._records:
            by_s[r.strategy.value] = by_s.get(r.strategy.value, 0) + 1
            by_sens[r.sensitivity.value] = by_sens.get(r.sensitivity.value, 0) + 1
            by_p[r.phase.value] = by_p.get(r.phase.value, 0) + 1
        exp_best: dict[str, float] = {}
        for r in self._records:
            if r.experiment_id not in exp_best or r.outcome_score > exp_best[r.experiment_id]:
                exp_best[r.experiment_id] = r.outcome_score
        top_exps = sorted(exp_best, key=lambda x: exp_best[x], reverse=True)[:10]
        recs_list: list[str] = []
        negligible = by_sens.get("negligible", 0)
        if negligible > 0:
            recs_list.append(f"{negligible} negligible-sensitivity parameters — prune search space")
        if by_p.get("exploration", 0) == 0 and by_p.get("exploitation", 0) > 0:
            recs_list.append("Consider wider exploration before exploitation")
        if not recs_list:
            recs_list.append("Parameter search is progressing efficiently")
        return ExperimentParameterReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            by_strategy=by_s,
            by_sensitivity=by_sens,
            by_phase=by_p,
            top_experiments=top_exps,
            recommendations=recs_list,
        )

    def get_stats(self) -> dict[str, Any]:
        s_dist: dict[str, int] = {}
        for r in self._records:
            s_dist[r.strategy.value] = s_dist.get(r.strategy.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "strategy_distribution": s_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("experiment_parameter_search.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def select_next_parameters(self, experiment_id: str) -> dict[str, Any]:
        """Select next parameter values to evaluate."""
        exp_recs = [r for r in self._records if r.experiment_id == experiment_id]
        if not exp_recs:
            return {"experiment_id": experiment_id, "next_value": None, "reason": "no_data"}
        by_param: dict[str, list[tuple[float, float]]] = {}
        for r in exp_recs:
            by_param.setdefault(r.parameter_name, []).append((r.parameter_value, r.outcome_score))
        suggestions: list[dict[str, Any]] = []
        for pname, pairs in by_param.items():
            best_pair = max(pairs, key=lambda x: x[1])
            vals = [p[0] for p in pairs]
            val_range = max(vals) - min(vals) if len(vals) > 1 else abs(best_pair[0]) * 0.1
            next_val = round(best_pair[0] + val_range * 0.1, 6)
            suggestions.append(
                {
                    "parameter_name": pname,
                    "suggested_value": next_val,
                    "best_known_value": best_pair[0],
                    "best_known_score": best_pair[1],
                    "trials_done": len(pairs),
                }
            )
        suggestions.sort(key=lambda x: x["best_known_score"], reverse=True)
        return {
            "experiment_id": experiment_id,
            "suggestions": suggestions,
            "total_parameters": len(suggestions),
        }

    def compute_parameter_sensitivity(self) -> list[dict[str, Any]]:
        """Compute sensitivity of each parameter to outcome score."""
        param_data: dict[str, list[tuple[float, float]]] = {}
        for r in self._records:
            param_data.setdefault(r.parameter_name, []).append((r.parameter_value, r.outcome_score))
        results: list[dict[str, Any]] = []
        for pname, pairs in param_data.items():
            if len(pairs) < 2:
                continue
            scores = [p[1] for p in pairs]
            score_range = max(scores) - min(scores)
            mean_score = sum(scores) / len(scores)
            var = sum((s - mean_score) ** 2 for s in scores) / len(scores)
            std_score = var**0.5
            sensitivity_label = "negligible"
            if score_range > 0.2:
                sensitivity_label = "high_impact"
            elif score_range > 0.1:
                sensitivity_label = "moderate_impact"
            elif score_range > 0.02:
                sensitivity_label = "low_impact"
            results.append(
                {
                    "parameter_name": pname,
                    "score_range": round(score_range, 6),
                    "score_std": round(std_score, 6),
                    "sensitivity": sensitivity_label,
                    "trials": len(pairs),
                }
            )
        results.sort(key=lambda x: x["score_range"], reverse=True)
        return results

    def estimate_remaining_search_value(self) -> list[dict[str, Any]]:
        """Estimate value left to find per experiment."""
        exp_scores: dict[str, list[float]] = {}
        for r in self._records:
            exp_scores.setdefault(r.experiment_id, []).append(r.outcome_score)
        results: list[dict[str, Any]] = []
        for eid, scores in exp_scores.items():
            best = max(scores)
            avg = sum(scores) / len(scores)
            std = (sum((s - avg) ** 2 for s in scores) / len(scores)) ** 0.5
            estimated_remaining = round(std * 1.5, 6)
            worth_continuing = estimated_remaining > 0.01
            results.append(
                {
                    "experiment_id": eid,
                    "best_score": round(best, 6),
                    "avg_score": round(avg, 6),
                    "score_std": round(std, 6),
                    "estimated_remaining_value": estimated_remaining,
                    "worth_continuing": worth_continuing,
                    "trials": len(scores),
                }
            )
        results.sort(key=lambda x: x["estimated_remaining_value"], reverse=True)
        return results
