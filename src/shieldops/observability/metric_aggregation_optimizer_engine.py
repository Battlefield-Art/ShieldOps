"""MetricAggregationOptimizerEngine — Optimize metric aggregation strategies."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TemporalityType(StrEnum):
    CUMULATIVE = "cumulative"
    DELTA = "delta"


class AggregationMethod(StrEnum):
    SUM = "sum"
    AVERAGE = "average"
    MIN = "min"
    MAX = "max"
    PERCENTILE = "percentile"


class OptimizationOutcome(StrEnum):
    REDUCED_CARDINALITY = "reduced_cardinality"
    IMPROVED_ACCURACY = "improved_accuracy"
    LOWER_COST = "lower_cost"


# --- Models ---


class MetricAggregationOptimizerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    temporality_type: TemporalityType = TemporalityType.CUMULATIVE
    aggregation_method: AggregationMethod = AggregationMethod.SUM
    optimization_outcome: OptimizationOutcome = OptimizationOutcome.REDUCED_CARDINALITY
    score: float = 0.0
    cardinality: int = 0
    rollup_interval_sec: int = 60
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class MetricAggregationOptimizerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    temporality_type: TemporalityType = TemporalityType.CUMULATIVE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MetricAggregationOptimizerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_temporality_type: dict[str, int] = Field(default_factory=dict)
    by_aggregation_method: dict[str, int] = Field(default_factory=dict)
    by_optimization_outcome: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class MetricAggregationOptimizerEngine:
    """Optimize metric aggregation strategies (temporality, alignment, rollup)."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[MetricAggregationOptimizerRecord] = []
        self._analyses: list[MetricAggregationOptimizerAnalysis] = []
        logger.info(
            "metric_aggregation_optimizer_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        temporality_type: TemporalityType = TemporalityType.CUMULATIVE,
        aggregation_method: AggregationMethod = AggregationMethod.SUM,
        optimization_outcome: OptimizationOutcome = OptimizationOutcome.REDUCED_CARDINALITY,
        score: float = 0.0,
        cardinality: int = 0,
        rollup_interval_sec: int = 60,
        service: str = "",
        team: str = "",
    ) -> MetricAggregationOptimizerRecord:
        record = MetricAggregationOptimizerRecord(
            name=name,
            temporality_type=temporality_type,
            aggregation_method=aggregation_method,
            optimization_outcome=optimization_outcome,
            score=score,
            cardinality=cardinality,
            rollup_interval_sec=rollup_interval_sec,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "metric_aggregation_optimizer_engine.record_added",
            record_id=record.id,
            name=name,
            temporality_type=temporality_type.value,
            aggregation_method=aggregation_method.value,
        )
        return record

    def get_record(self, record_id: str) -> MetricAggregationOptimizerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        temporality_type: TemporalityType | None = None,
        aggregation_method: AggregationMethod | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[MetricAggregationOptimizerRecord]:
        results = list(self._records)
        if temporality_type is not None:
            results = [r for r in results if r.temporality_type == temporality_type]
        if aggregation_method is not None:
            results = [r for r in results if r.aggregation_method == aggregation_method]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        temporality_type: TemporalityType = TemporalityType.CUMULATIVE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> MetricAggregationOptimizerAnalysis:
        analysis = MetricAggregationOptimizerAnalysis(
            name=name,
            temporality_type=temporality_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "metric_aggregation_optimizer_engine.analysis_added",
            name=name,
            temporality_type=temporality_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def evaluate_aggregation_efficiency(self) -> list[dict[str, Any]]:
        """Evaluate how efficiently metrics are being aggregated."""
        svc_data: dict[str, list[MetricAggregationOptimizerRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            total_cardinality = sum(r.cardinality for r in records)
            avg_score = round(sum(r.score for r in records) / len(records), 2)
            methods_used = list({r.aggregation_method.value for r in records})
            results.append(
                {
                    "service": svc,
                    "metric_count": len(records),
                    "total_cardinality": total_cardinality,
                    "avg_efficiency_score": avg_score,
                    "methods_used": methods_used,
                    "efficiency": "high" if avg_score >= self._threshold else "low",
                }
            )
        return sorted(results, key=lambda x: x["avg_efficiency_score"])

    def detect_temporal_misalignment(self) -> list[dict[str, Any]]:
        """Detect metrics with misaligned temporality within the same service."""
        svc_temp: dict[str, dict[str, int]] = {}
        for r in self._records:
            svc_temp.setdefault(r.service, {})
            t = r.temporality_type.value
            svc_temp[r.service][t] = svc_temp[r.service].get(t, 0) + 1
        issues: list[dict[str, Any]] = []
        for svc, temps in svc_temp.items():
            if len(temps) > 1:
                issues.append(
                    {
                        "service": svc,
                        "temporality_mix": temps,
                        "issue": "mixed_temporality",
                        "severity": "warning",
                        "suggestion": "Align all metrics to a single temporality type",
                    }
                )
        return issues

    def recommend_rollup_strategy(self) -> list[dict[str, Any]]:
        """Recommend rollup strategies to reduce cardinality and cost."""
        recommendations: list[dict[str, Any]] = []
        high_cardinality = [r for r in self._records if r.cardinality > 1000]
        for r in high_cardinality:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "cardinality": r.cardinality,
                    "current_rollup": r.rollup_interval_sec,
                    "priority": "high",
                    "suggestion": f"Increase rollup interval from {r.rollup_interval_sec}s "
                    f"to reduce cardinality ({r.cardinality})",
                }
            )
        low_score = [
            r for r in self._records if r.score < self._threshold and r.cardinality <= 1000
        ]
        for r in low_score:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "cardinality": r.cardinality,
                    "current_rollup": r.rollup_interval_sec,
                    "priority": "medium",
                    "suggestion": f"Optimize aggregation method (score: {r.score})",
                }
            )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else 1,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.temporality_type.value
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
                        "temporality_type": r.temporality_type.value,
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

    def generate_report(self) -> MetricAggregationOptimizerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.temporality_type.value] = by_e1.get(r.temporality_type.value, 0) + 1
            by_e2[r.aggregation_method.value] = by_e2.get(r.aggregation_method.value, 0) + 1
            by_e3[r.optimization_outcome.value] = by_e3.get(r.optimization_outcome.value, 0) + 1
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
            recs.append("Metric Aggregation Optimizer Engine is healthy")
        return MetricAggregationOptimizerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_temporality_type=by_e1,
            by_aggregation_method=by_e2,
            by_optimization_outcome=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("metric_aggregation_optimizer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.temporality_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "temporality_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
