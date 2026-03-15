"""AgentMetaLearningEngine — Meta-learning across agent fleet."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MetaStrategy(StrEnum):
    TRANSFER = "transfer"
    CURRICULUM = "curriculum"
    ENSEMBLE = "ensemble"
    DISTILLATION = "distillation"


class LearningOutcome(StrEnum):
    IMPROVED = "improved"
    UNCHANGED = "unchanged"
    DEGRADED = "degraded"


class AgentGeneration(StrEnum):
    GEN1 = "gen1"
    GEN2 = "gen2"
    GEN3 = "gen3"
    EXPERIMENTAL = "experimental"


# --- Models ---


class AgentMetaLearningRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    meta_strategy: MetaStrategy = MetaStrategy.TRANSFER
    learning_outcome: LearningOutcome = LearningOutcome.IMPROVED
    agent_generation: AgentGeneration = AgentGeneration.GEN1
    score: float = 0.0
    improvement_pct: float = 0.0
    training_cost: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentMetaLearningAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    meta_strategy: MetaStrategy = MetaStrategy.TRANSFER
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentMetaLearningReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_meta_strategy: dict[str, int] = Field(default_factory=dict)
    by_learning_outcome: dict[str, int] = Field(default_factory=dict)
    by_agent_generation: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentMetaLearningEngine:
    """Meta-learning across agent fleet — learn what learning strategies work best."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AgentMetaLearningRecord] = []
        self._analyses: list[AgentMetaLearningAnalysis] = []
        logger.info(
            "agent_meta_learning_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        meta_strategy: MetaStrategy = MetaStrategy.TRANSFER,
        learning_outcome: LearningOutcome = LearningOutcome.IMPROVED,
        agent_generation: AgentGeneration = AgentGeneration.GEN1,
        score: float = 0.0,
        improvement_pct: float = 0.0,
        training_cost: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> AgentMetaLearningRecord:
        record = AgentMetaLearningRecord(
            name=name,
            meta_strategy=meta_strategy,
            learning_outcome=learning_outcome,
            agent_generation=agent_generation,
            score=score,
            improvement_pct=improvement_pct,
            training_cost=training_cost,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_meta_learning_engine.record_added",
            record_id=record.id,
            name=name,
            meta_strategy=meta_strategy.value,
            learning_outcome=learning_outcome.value,
        )
        return record

    def get_record(self, record_id: str) -> AgentMetaLearningRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        meta_strategy: MetaStrategy | None = None,
        learning_outcome: LearningOutcome | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AgentMetaLearningRecord]:
        results = list(self._records)
        if meta_strategy is not None:
            results = [r for r in results if r.meta_strategy == meta_strategy]
        if learning_outcome is not None:
            results = [r for r in results if r.learning_outcome == learning_outcome]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        meta_strategy: MetaStrategy = MetaStrategy.TRANSFER,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AgentMetaLearningAnalysis:
        analysis = AgentMetaLearningAnalysis(
            name=name,
            meta_strategy=meta_strategy,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "agent_meta_learning_engine.analysis_added",
            name=name,
            meta_strategy=meta_strategy.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_best_learning_strategies(self) -> list[dict[str, Any]]:
        """Identify which meta-learning strategies produce best outcomes."""
        strategy_data: dict[str, list[AgentMetaLearningRecord]] = {}
        for r in self._records:
            strategy_data.setdefault(r.meta_strategy.value, []).append(r)
        results: list[dict[str, Any]] = []
        for strategy, records in strategy_data.items():
            total = len(records)
            improved = sum(1 for r in records if r.learning_outcome == LearningOutcome.IMPROVED)
            avg_improvement = (
                round(sum(r.improvement_pct for r in records) / total, 2) if total else 0.0
            )
            avg_cost = round(sum(r.training_cost for r in records) / total, 2) if total else 0.0
            results.append(
                {
                    "strategy": strategy,
                    "total_trials": total,
                    "improved_count": improved,
                    "success_rate": round(improved / total * 100, 1) if total else 0.0,
                    "avg_improvement_pct": avg_improvement,
                    "avg_training_cost": avg_cost,
                    "cost_efficiency": round(avg_improvement / avg_cost, 4)
                    if avg_cost > 0
                    else 0.0,
                }
            )
        return sorted(results, key=lambda x: x["success_rate"], reverse=True)

    def cross_pollinate_agent_knowledge(self) -> list[dict[str, Any]]:
        """Identify knowledge transfer opportunities across agent generations."""
        gen_strategies: dict[str, dict[str, list[float]]] = {}
        for r in self._records:
            gen = r.agent_generation.value
            strat = r.meta_strategy.value
            gen_strategies.setdefault(gen, {}).setdefault(strat, []).append(r.improvement_pct)
        opportunities: list[dict[str, Any]] = []
        gens = list(gen_strategies.keys())
        for i, gen_from in enumerate(gens):
            for gen_to in gens[i + 1 :]:
                from_strats = gen_strategies[gen_from]
                to_strats = gen_strategies[gen_to]
                unique_to_from = set(from_strats.keys()) - set(to_strats.keys())
                for strat in unique_to_from:
                    avg_imp = round(sum(from_strats[strat]) / len(from_strats[strat]), 2)
                    if avg_imp > 0:
                        opportunities.append(
                            {
                                "from_generation": gen_from,
                                "to_generation": gen_to,
                                "strategy": strat,
                                "avg_improvement_in_source": avg_imp,
                                "potential": "high" if avg_imp > 10 else "medium",
                            }
                        )
        return sorted(
            opportunities,
            key=lambda x: x["avg_improvement_in_source"],
            reverse=True,
        )

    def evaluate_meta_learning_roi(self) -> list[dict[str, Any]]:
        """Evaluate ROI of meta-learning investments per strategy."""
        strategy_costs: dict[str, list[AgentMetaLearningRecord]] = {}
        for r in self._records:
            strategy_costs.setdefault(r.meta_strategy.value, []).append(r)
        results: list[dict[str, Any]] = []
        for strategy, records in strategy_costs.items():
            total_cost = sum(r.training_cost for r in records)
            total_improvement = sum(r.improvement_pct for r in records)
            degraded = sum(1 for r in records if r.learning_outcome == LearningOutcome.DEGRADED)
            roi = round(total_improvement / total_cost, 4) if total_cost > 0 else 0.0
            results.append(
                {
                    "strategy": strategy,
                    "total_cost": round(total_cost, 2),
                    "total_improvement": round(total_improvement, 2),
                    "roi": roi,
                    "degraded_count": degraded,
                    "risk_adjusted_roi": round(roi * (1 - degraded / len(records)), 4)
                    if records
                    else 0.0,
                }
            )
        return sorted(results, key=lambda x: x["roi"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.meta_strategy.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "meta_strategy": r.meta_strategy.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> AgentMetaLearningReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.meta_strategy.value] = by_e1.get(r.meta_strategy.value, 0) + 1
            by_e2[r.learning_outcome.value] = by_e2.get(r.learning_outcome.value, 0) + 1
            by_e3[r.agent_generation.value] = by_e3.get(r.agent_generation.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Agent Meta Learning Engine is healthy")
        return AgentMetaLearningReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_meta_strategy=by_e1,
            by_learning_outcome=by_e2,
            by_agent_generation=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_meta_learning_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.meta_strategy.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "meta_strategy_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
