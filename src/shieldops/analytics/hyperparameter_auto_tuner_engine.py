"""Hyperparameter Auto-Tuner Engine — autoresearch-style agent parameter tuning."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TuningStrategy(StrEnum):
    GRID_SEARCH = "grid_search"
    RANDOM_SEARCH = "random_search"
    BAYESIAN = "bayesian"
    EVOLUTIONARY = "evolutionary"


class ParameterType(StrEnum):
    THRESHOLD = "threshold"
    TIMEOUT = "timeout"
    BATCH_SIZE = "batch_size"
    LEARNING_RATE = "learning_rate"


class TuningOutcome(StrEnum):
    IMPROVED = "improved"
    NO_CHANGE = "no_change"
    DEGRADED = "degraded"
    INVALID = "invalid"


# --- Models ---


class TuningRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    strategy: TuningStrategy = TuningStrategy.BAYESIAN
    parameter_type: ParameterType = ParameterType.THRESHOLD
    outcome: TuningOutcome = TuningOutcome.NO_CHANGE
    score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class TuningAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    strategy: TuningStrategy = TuningStrategy.BAYESIAN
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TuningReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    degraded_count: int = 0
    avg_score: float = 0.0
    by_strategy: dict[str, int] = Field(default_factory=dict)
    by_parameter: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    top_degraded: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class HyperparameterAutoTunerEngine:
    """Automatically tune agent hyperparameters using propose-evaluate-accept/reject."""

    def __init__(
        self,
        max_records: int = 200000,
        improvement_threshold: float = 5.0,
    ) -> None:
        self._max_records = max_records
        self._improvement_threshold = improvement_threshold
        self._records: list[TuningRecord] = []
        self._analyses: list[TuningAnalysis] = []
        logger.info(
            "hyperparameter_auto_tuner_engine.initialized",
            max_records=max_records,
            improvement_threshold=improvement_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        agent_id: str,
        strategy: TuningStrategy = TuningStrategy.BAYESIAN,
        parameter_type: ParameterType = ParameterType.THRESHOLD,
        outcome: TuningOutcome = TuningOutcome.NO_CHANGE,
        score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> TuningRecord:
        record = TuningRecord(
            agent_id=agent_id,
            strategy=strategy,
            parameter_type=parameter_type,
            outcome=outcome,
            score=score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "hyperparameter_auto_tuner_engine.record_added",
            record_id=record.id,
            agent_id=agent_id,
            strategy=strategy.value,
            outcome=outcome.value,
        )
        return record

    def get_record(self, record_id: str) -> TuningRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        strategy: TuningStrategy | None = None,
        parameter_type: ParameterType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[TuningRecord]:
        results = list(self._records)
        if strategy is not None:
            results = [r for r in results if r.strategy == strategy]
        if parameter_type is not None:
            results = [r for r in results if r.parameter_type == parameter_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        agent_id: str,
        strategy: TuningStrategy = TuningStrategy.BAYESIAN,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> TuningAnalysis:
        analysis = TuningAnalysis(
            agent_id=agent_id,
            strategy=strategy,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "hyperparameter_auto_tuner_engine.analysis_added",
            agent_id=agent_id,
            strategy=strategy.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def propose_parameter_change(self, agent_id: str) -> dict[str, Any]:
        """Suggest next parameter to tune based on tuning history."""
        agent_records = [r for r in self._records if r.agent_id == agent_id]
        if not agent_records:
            return {
                "agent_id": agent_id,
                "proposed_parameter": ParameterType.THRESHOLD.value,
                "proposed_strategy": TuningStrategy.BAYESIAN.value,
                "reason": "no_history_default_proposal",
            }
        param_scores: dict[str, list[float]] = {}
        for r in agent_records:
            param_scores.setdefault(r.parameter_type.value, []).append(r.score)
        worst_param = min(
            param_scores,
            key=lambda p: sum(param_scores[p]) / len(param_scores[p]),
        )
        strategy_outcomes: dict[str, int] = {}
        for r in agent_records:
            if r.outcome == TuningOutcome.IMPROVED:
                key = r.strategy.value
                strategy_outcomes[key] = strategy_outcomes.get(key, 0) + 1
        best_strategy = (
            max(strategy_outcomes, key=strategy_outcomes.get)  # type: ignore[arg-type]
            if strategy_outcomes
            else TuningStrategy.BAYESIAN.value
        )
        return {
            "agent_id": agent_id,
            "proposed_parameter": worst_param,
            "proposed_strategy": best_strategy,
            "reason": "lowest_avg_score_parameter",
        }

    def evaluate_tuning_result(self, experiment_id: str) -> dict[str, Any]:
        """Accept/reject a tuning experiment based on improvement threshold."""
        record = self.get_record(experiment_id)
        if record is None:
            return {
                "experiment_id": experiment_id,
                "decision": "not_found",
                "reason": "experiment_not_found",
            }
        agent_records = [
            r for r in self._records if r.agent_id == record.agent_id and r.id != record.id
        ]
        if not agent_records:
            decision = "accept" if record.score > 0 else "reject"
            return {
                "experiment_id": experiment_id,
                "decision": decision,
                "score": record.score,
                "reason": "no_prior_baseline",
            }
        prior_avg = sum(r.score for r in agent_records) / len(agent_records)
        delta = round(record.score - prior_avg, 2)
        if delta >= self._improvement_threshold:
            decision = "accept"
        elif delta > -self._improvement_threshold:
            decision = "neutral"
        else:
            decision = "reject"
        return {
            "experiment_id": experiment_id,
            "decision": decision,
            "score": record.score,
            "prior_avg": round(prior_avg, 2),
            "delta": delta,
        }

    def compute_optimal_parameters(self, agent_id: str) -> dict[str, Any]:
        """Find best parameters from tuning history for an agent."""
        agent_records = [r for r in self._records if r.agent_id == agent_id]
        if not agent_records:
            return {"agent_id": agent_id, "optimal_parameters": {}}
        param_best: dict[str, dict[str, Any]] = {}
        for r in agent_records:
            key = r.parameter_type.value
            if key not in param_best or r.score > param_best[key]["best_score"]:
                param_best[key] = {
                    "best_score": r.score,
                    "strategy": r.strategy.value,
                    "outcome": r.outcome.value,
                }
        return {
            "agent_id": agent_id,
            "optimal_parameters": param_best,
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> TuningReport:
        by_strategy: dict[str, int] = {}
        by_parameter: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        for r in self._records:
            by_strategy[r.strategy.value] = by_strategy.get(r.strategy.value, 0) + 1
            by_parameter[r.parameter_type.value] = by_parameter.get(r.parameter_type.value, 0) + 1
            by_outcome[r.outcome.value] = by_outcome.get(r.outcome.value, 0) + 1
        degraded_count = sum(1 for r in self._records if r.outcome == TuningOutcome.DEGRADED)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        degraded_agents = [r.agent_id for r in self._records if r.outcome == TuningOutcome.DEGRADED]
        top_degraded = list(dict.fromkeys(degraded_agents))[:5]
        recs: list[str] = []
        if self._records and degraded_count > 0:
            recs.append(f"{degraded_count} tuning experiment(s) resulted in degradation")
        if self._records and avg_score < self._improvement_threshold:
            recs.append(
                f"Avg tuning score {avg_score} below improvement threshold "
                f"({self._improvement_threshold})"
            )
        if not recs:
            recs.append("Hyperparameter tuning is healthy")
        return TuningReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            degraded_count=degraded_count,
            avg_score=avg_score,
            by_strategy=by_strategy,
            by_parameter=by_parameter,
            by_outcome=by_outcome,
            top_degraded=top_degraded,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("hyperparameter_auto_tuner_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        strategy_dist: dict[str, int] = {}
        for r in self._records:
            key = r.strategy.value
            strategy_dist[key] = strategy_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "improvement_threshold": self._improvement_threshold,
            "strategy_distribution": strategy_dist,
            "unique_agents": len({r.agent_id for r in self._records}),
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
