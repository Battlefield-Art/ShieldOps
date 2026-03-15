"""AdaptiveThresholdEngine — auto-adjust risk thresholds based on baseline drift."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DriftDirection(StrEnum):
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"


class AdaptationStrategy(StrEnum):
    CONSERVATIVE = "conservative"
    MODERATE = "moderate"
    AGGRESSIVE = "aggressive"


class ThresholdStatus(StrEnum):
    ACTIVE = "active"
    PROPOSED = "proposed"
    RETIRED = "retired"


# --- Models ---


class AdaptiveThresholdRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    drift_direction: DriftDirection = DriftDirection.STABLE
    adaptation_strategy: AdaptationStrategy = AdaptationStrategy.MODERATE
    threshold_status: ThresholdStatus = ThresholdStatus.ACTIVE
    score: float = 0.0
    current_threshold: float = 0.0
    baseline_value: float = 0.0
    entity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AdaptiveThresholdAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    drift_direction: DriftDirection = DriftDirection.STABLE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AdaptiveThresholdReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_drift_direction: dict[str, int] = Field(default_factory=dict)
    by_adaptation_strategy: dict[str, int] = Field(default_factory=dict)
    by_threshold_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AdaptiveThresholdEngine:
    """Auto-adjust risk thresholds based on baseline drift."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AdaptiveThresholdRecord] = []
        self._analyses: list[AdaptiveThresholdAnalysis] = []
        logger.info(
            "adaptive_threshold_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        drift_direction: DriftDirection = DriftDirection.STABLE,
        adaptation_strategy: AdaptationStrategy = AdaptationStrategy.MODERATE,
        threshold_status: ThresholdStatus = ThresholdStatus.ACTIVE,
        score: float = 0.0,
        current_threshold: float = 0.0,
        baseline_value: float = 0.0,
        entity: str = "",
        service: str = "",
        team: str = "",
    ) -> AdaptiveThresholdRecord:
        record = AdaptiveThresholdRecord(
            name=name,
            drift_direction=drift_direction,
            adaptation_strategy=adaptation_strategy,
            threshold_status=threshold_status,
            score=score,
            current_threshold=current_threshold,
            baseline_value=baseline_value,
            entity=entity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "adaptive_threshold_engine.record_added",
            record_id=record.id,
            name=name,
            drift_direction=drift_direction.value,
            threshold_status=threshold_status.value,
        )
        return record

    def get_record(self, record_id: str) -> AdaptiveThresholdRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        drift_direction: DriftDirection | None = None,
        threshold_status: ThresholdStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AdaptiveThresholdRecord]:
        results = list(self._records)
        if drift_direction is not None:
            results = [r for r in results if r.drift_direction == drift_direction]
        if threshold_status is not None:
            results = [r for r in results if r.threshold_status == threshold_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        drift_direction: DriftDirection = DriftDirection.STABLE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AdaptiveThresholdAnalysis:
        analysis = AdaptiveThresholdAnalysis(
            name=name,
            drift_direction=drift_direction,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "adaptive_threshold_engine.analysis_added",
            name=name,
            drift_direction=drift_direction.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_optimal_thresholds(self) -> list[dict[str, Any]]:
        """Compute optimal thresholds based on baseline and drift patterns."""
        entity_data: dict[str, list[AdaptiveThresholdRecord]] = {}
        for r in self._records:
            entity_data.setdefault(r.entity, []).append(r)
        results: list[dict[str, Any]] = []
        for entity, records in entity_data.items():
            baselines = [r.baseline_value for r in records]
            current_thresholds = [r.current_threshold for r in records]
            avg_baseline = sum(baselines) / len(baselines)
            avg_threshold = sum(current_thresholds) / len(current_thresholds)
            # Optimal is baseline + margin based on strategy
            latest = records[-1]
            if latest.adaptation_strategy == AdaptationStrategy.CONSERVATIVE:
                margin = 0.3
            elif latest.adaptation_strategy == AdaptationStrategy.AGGRESSIVE:
                margin = 0.1
            else:
                margin = 0.2
            optimal = round(avg_baseline * (1 + margin), 2)
            results.append(
                {
                    "entity": entity,
                    "current_threshold": round(avg_threshold, 2),
                    "optimal_threshold": optimal,
                    "avg_baseline": round(avg_baseline, 2),
                    "strategy": latest.adaptation_strategy.value,
                    "adjustment_needed": abs(optimal - avg_threshold) > 5.0,
                }
            )
        return sorted(
            results,
            key=lambda x: abs(x["optimal_threshold"] - x["current_threshold"]),
            reverse=True,
        )

    def detect_threshold_staleness(self) -> list[dict[str, Any]]:
        """Detect thresholds that haven't been updated despite baseline changes."""
        stale: list[dict[str, Any]] = []
        entity_data: dict[str, list[AdaptiveThresholdRecord]] = {}
        for r in self._records:
            entity_data.setdefault(r.entity, []).append(r)
        for entity, records in entity_data.items():
            if len(records) < 2:
                continue
            first = records[0]
            latest = records[-1]
            baseline_change = abs(latest.baseline_value - first.baseline_value)
            threshold_change = abs(latest.current_threshold - first.current_threshold)
            if baseline_change > 10.0 and threshold_change < 2.0:
                stale.append(
                    {
                        "entity": entity,
                        "baseline_drift": round(baseline_change, 2),
                        "threshold_drift": round(threshold_change, 2),
                        "staleness": "high" if baseline_change > 20.0 else "moderate",
                        "records_analyzed": len(records),
                    }
                )
        return sorted(stale, key=lambda x: x["baseline_drift"], reverse=True)

    def evaluate_adaptation_impact(self) -> dict[str, Any]:
        """Evaluate the impact of threshold adaptations on detection quality."""
        strategy_data: dict[str, list[float]] = {}
        for r in self._records:
            strategy_data.setdefault(r.adaptation_strategy.value, []).append(r.score)
        impact: dict[str, Any] = {}
        for strategy, scores in strategy_data.items():
            avg = sum(scores) / len(scores)
            impact[strategy] = {
                "avg_score": round(avg, 2),
                "sample_count": len(scores),
                "above_threshold_pct": round(
                    sum(1 for s in scores if s >= self._threshold) / len(scores) * 100, 1
                ),
            }
        return impact

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.drift_direction.value
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
                        "drift_direction": r.drift_direction.value,
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

    def generate_report(self) -> AdaptiveThresholdReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.drift_direction.value] = by_e1.get(r.drift_direction.value, 0) + 1
            by_e2[r.adaptation_strategy.value] = by_e2.get(r.adaptation_strategy.value, 0) + 1
            by_e3[r.threshold_status.value] = by_e3.get(r.threshold_status.value, 0) + 1
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
            recs.append("Adaptive Threshold Engine is healthy")
        return AdaptiveThresholdReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_drift_direction=by_e1,
            by_adaptation_strategy=by_e2,
            by_threshold_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("adaptive_threshold_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.drift_direction.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "drift_direction_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
