"""ExperimentReplayEngine — replay and analyze past experiments for meta-learning."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ReplayOutcome(StrEnum):
    CONFIRMED = "confirmed"
    CONTRADICTED = "contradicted"
    INCONCLUSIVE = "inconclusive"


class InsightType(StrEnum):
    CAUSAL = "causal"
    CORRELATIONAL = "correlational"
    SPURIOUS = "spurious"


class ReplayStrategy(StrEnum):
    EXACT = "exact"
    PERTURBED = "perturbed"
    COUNTERFACTUAL = "counterfactual"


# --- Models ---


class ExperimentReplayRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    replay_outcome: ReplayOutcome = ReplayOutcome.INCONCLUSIVE
    insight_type: InsightType = InsightType.CORRELATIONAL
    replay_strategy: ReplayStrategy = ReplayStrategy.EXACT
    score: float = 0.0
    original_score: float = 0.0
    replay_score: float = 0.0
    experiment_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ExperimentReplayAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    replay_outcome: ReplayOutcome = ReplayOutcome.INCONCLUSIVE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ExperimentReplayReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_replay_outcome: dict[str, int] = Field(default_factory=dict)
    by_insight_type: dict[str, int] = Field(default_factory=dict)
    by_replay_strategy: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ExperimentReplayEngine:
    """Replay and analyze past experiments for meta-learning."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[ExperimentReplayRecord] = []
        self._analyses: list[ExperimentReplayAnalysis] = []
        logger.info(
            "experiment_replay_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        replay_outcome: ReplayOutcome = ReplayOutcome.INCONCLUSIVE,
        insight_type: InsightType = InsightType.CORRELATIONAL,
        replay_strategy: ReplayStrategy = ReplayStrategy.EXACT,
        score: float = 0.0,
        original_score: float = 0.0,
        replay_score: float = 0.0,
        experiment_id: str = "",
        service: str = "",
        team: str = "",
    ) -> ExperimentReplayRecord:
        record = ExperimentReplayRecord(
            name=name,
            replay_outcome=replay_outcome,
            insight_type=insight_type,
            replay_strategy=replay_strategy,
            score=score,
            original_score=original_score,
            replay_score=replay_score,
            experiment_id=experiment_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "experiment_replay_engine.record_added",
            record_id=record.id,
            name=name,
            replay_outcome=replay_outcome.value,
            replay_strategy=replay_strategy.value,
        )
        return record

    def get_record(self, record_id: str) -> ExperimentReplayRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        replay_outcome: ReplayOutcome | None = None,
        replay_strategy: ReplayStrategy | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ExperimentReplayRecord]:
        results = list(self._records)
        if replay_outcome is not None:
            results = [r for r in results if r.replay_outcome == replay_outcome]
        if replay_strategy is not None:
            results = [r for r in results if r.replay_strategy == replay_strategy]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        replay_outcome: ReplayOutcome = ReplayOutcome.INCONCLUSIVE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ExperimentReplayAnalysis:
        analysis = ExperimentReplayAnalysis(
            name=name,
            replay_outcome=replay_outcome,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "experiment_replay_engine.analysis_added",
            name=name,
            replay_outcome=replay_outcome.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_replayable_experiments(self) -> list[dict[str, Any]]:
        """Find experiments suitable for replay based on score and outcome."""
        exp_data: dict[str, list[ExperimentReplayRecord]] = {}
        for r in self._records:
            exp_data.setdefault(r.experiment_id, []).append(r)
        replayable: list[dict[str, Any]] = []
        for exp_id, records in exp_data.items():
            outcomes = [r.replay_outcome for r in records]
            inconclusive = sum(1 for o in outcomes if o == ReplayOutcome.INCONCLUSIVE)
            scores = [r.score for r in records]
            avg_score = sum(scores) / len(scores)
            if inconclusive > 0 or avg_score < self._threshold:
                replayable.append(
                    {
                        "experiment_id": exp_id,
                        "replay_count": len(records),
                        "inconclusive_count": inconclusive,
                        "avg_score": round(avg_score, 2),
                        "replayability": (
                            "high" if inconclusive > len(records) * 0.5 else "moderate"
                        ),
                    }
                )
        return sorted(replayable, key=lambda x: x["inconclusive_count"], reverse=True)

    def analyze_replay_divergence(self) -> list[dict[str, Any]]:
        """Analyze divergence between original and replay scores."""
        divergences: list[dict[str, Any]] = []
        for r in self._records:
            if r.original_score > 0 or r.replay_score > 0:
                delta = abs(r.replay_score - r.original_score)
                divergences.append(
                    {
                        "record_id": r.id,
                        "experiment_id": r.experiment_id,
                        "name": r.name,
                        "original_score": r.original_score,
                        "replay_score": r.replay_score,
                        "delta": round(delta, 2),
                        "divergence": (
                            "high" if delta > 20.0 else "moderate" if delta > 10.0 else "low"
                        ),
                    }
                )
        return sorted(divergences, key=lambda x: x["delta"], reverse=True)

    def extract_meta_insights(self) -> dict[str, Any]:
        """Extract meta-learning insights from replay patterns."""
        insight_data: dict[str, list[ExperimentReplayRecord]] = {}
        for r in self._records:
            insight_data.setdefault(r.insight_type.value, []).append(r)
        insights: dict[str, Any] = {}
        for itype, records in insight_data.items():
            confirmed = sum(1 for r in records if r.replay_outcome == ReplayOutcome.CONFIRMED)
            contradicted = sum(1 for r in records if r.replay_outcome == ReplayOutcome.CONTRADICTED)
            scores = [r.score for r in records]
            insights[itype] = {
                "total": len(records),
                "confirmed": confirmed,
                "contradicted": contradicted,
                "confirmation_rate": round(confirmed / len(records) * 100, 1) if records else 0.0,
                "avg_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
                "reliability": (
                    "high"
                    if confirmed > contradicted * 2
                    else "low"
                    if contradicted > confirmed
                    else "moderate"
                ),
            }
        return insights

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.replay_outcome.value
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
                        "replay_outcome": r.replay_outcome.value,
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

    def generate_report(self) -> ExperimentReplayReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.replay_outcome.value] = by_e1.get(r.replay_outcome.value, 0) + 1
            by_e2[r.insight_type.value] = by_e2.get(r.insight_type.value, 0) + 1
            by_e3[r.replay_strategy.value] = by_e3.get(r.replay_strategy.value, 0) + 1
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
            recs.append("Experiment Replay Engine is healthy")
        return ExperimentReplayReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_replay_outcome=by_e1,
            by_insight_type=by_e2,
            by_replay_strategy=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("experiment_replay_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.replay_outcome.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "replay_outcome_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
