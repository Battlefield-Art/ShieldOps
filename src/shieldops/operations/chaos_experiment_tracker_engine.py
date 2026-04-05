"""Chaos Experiment Tracker Engine — track chaos engineering experiments."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ExperimentType(StrEnum):
    POD_KILL = "pod_kill"
    NETWORK_LATENCY = "network_latency"
    CPU_STRESS = "cpu_stress"
    MEMORY_PRESSURE = "memory_pressure"
    DNS_FAILURE = "dns_failure"


class HypothesisOutcome(StrEnum):
    CONFIRMED = "confirmed"
    DISPROVED = "disproved"
    INCONCLUSIVE = "inconclusive"
    PARTIALLY_CONFIRMED = "partially_confirmed"
    NOT_TESTED = "not_tested"


class ResilienceScore(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    MODERATE = "moderate"
    POOR = "poor"
    FAILING = "failing"


# --- Models ---


class ChaosExperimentTrackerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_name: str = ""
    service_id: str = ""
    experiment_type: ExperimentType = ExperimentType.POD_KILL
    hypothesis_outcome: HypothesisOutcome = HypothesisOutcome.NOT_TESTED
    resilience_score: ResilienceScore = ResilienceScore.MODERATE
    duration_seconds: float = 0.0
    recovery_time_seconds: float = 0.0
    error_rate_during: float = 0.0
    blast_radius: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ChaosExperimentTrackerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    analysis_score: float = 0.0
    experiment_type: ExperimentType = ExperimentType.POD_KILL
    resilience_improving: bool = False
    data_points: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ChaosExperimentTrackerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_recovery_time: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    by_resilience: dict[str, int] = Field(default_factory=dict)
    weak_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ChaosExperimentTrackerEngine:
    """Track chaos engineering experiments and resilience outcomes."""

    def __init__(
        self,
        max_records: int = 200000,
        resilience_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._resilience_threshold = resilience_threshold
        self._records: list[ChaosExperimentTrackerRecord] = []
        self._analyses: dict[str, ChaosExperimentTrackerAnalysis] = {}
        logger.info(
            "chaos_experiment_tracker_engine.init",
            max_records=max_records,
            resilience_threshold=resilience_threshold,
        )

    def add_record(
        self,
        experiment_name: str = "",
        service_id: str = "",
        experiment_type: ExperimentType = ExperimentType.POD_KILL,
        hypothesis_outcome: HypothesisOutcome = HypothesisOutcome.NOT_TESTED,
        resilience_score: ResilienceScore = ResilienceScore.MODERATE,
        duration_seconds: float = 0.0,
        recovery_time_seconds: float = 0.0,
        error_rate_during: float = 0.0,
        blast_radius: int = 0,
        description: str = "",
    ) -> ChaosExperimentTrackerRecord:
        record = ChaosExperimentTrackerRecord(
            experiment_name=experiment_name,
            service_id=service_id,
            experiment_type=experiment_type,
            hypothesis_outcome=hypothesis_outcome,
            resilience_score=resilience_score,
            duration_seconds=duration_seconds,
            recovery_time_seconds=recovery_time_seconds,
            error_rate_during=error_rate_during,
            blast_radius=blast_radius,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "chaos_experiment_tracker_engine.record_added",
            record_id=record.id,
            experiment_name=experiment_name,
        )
        return record

    def process(
        self,
        key: str,
    ) -> ChaosExperimentTrackerAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        svc_recs = [r for r in self._records if r.service_id == rec.service_id]
        score_map = {
            ResilienceScore.EXCELLENT: 100,
            ResilienceScore.GOOD: 80,
            ResilienceScore.MODERATE: 60,
            ResilienceScore.POOR: 30,
            ResilienceScore.FAILING: 0,
        }
        scores = [score_map.get(r.resilience_score, 50) for r in svc_recs]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        # Check if improving over time
        improving = False
        if len(scores) >= 4:
            mid = len(scores) // 2
            first = sum(scores[:mid]) / mid
            second = sum(scores[mid:]) / len(scores[mid:])
            improving = second > first
        analysis = ChaosExperimentTrackerAnalysis(
            service_id=rec.service_id,
            analysis_score=avg_score,
            experiment_type=rec.experiment_type,
            resilience_improving=improving,
            data_points=len(svc_recs),
            description=(f"Resilience score {avg_score} for {rec.service_id}"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ChaosExperimentTrackerReport:
        by_t: dict[str, int] = {}
        by_o: dict[str, int] = {}
        by_r: dict[str, int] = {}
        recovery_times: list[float] = []
        for r in self._records:
            by_t[r.experiment_type.value] = by_t.get(r.experiment_type.value, 0) + 1
            by_o[r.hypothesis_outcome.value] = by_o.get(r.hypothesis_outcome.value, 0) + 1
            by_r[r.resilience_score.value] = by_r.get(r.resilience_score.value, 0) + 1
            if r.recovery_time_seconds > 0:
                recovery_times.append(r.recovery_time_seconds)
        avg_recovery = (
            round(sum(recovery_times) / len(recovery_times), 2) if recovery_times else 0.0
        )
        weak = list(
            {
                r.service_id
                for r in self._records
                if r.resilience_score in (ResilienceScore.POOR, ResilienceScore.FAILING)
            }
        )[:10]
        recs: list[str] = []
        disproved = by_o.get(HypothesisOutcome.DISPROVED.value, 0)
        if disproved:
            recs.append(f"{disproved} experiments disproved hypothesis — investigate weaknesses")
        if weak:
            recs.append(f"{len(weak)} services with poor resilience scores")
        if not recs:
            recs.append("Chaos experiments healthy — resilience within targets")
        return ChaosExperimentTrackerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_recovery_time=avg_recovery,
            by_type=by_t,
            by_outcome=by_o,
            by_resilience=by_r,
            weak_services=weak,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            k = r.experiment_type.value
            type_dist[k] = type_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "resilience_threshold": self._resilience_threshold,
            "type_distribution": type_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("chaos_experiment_tracker_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def rank_services_by_resilience(self) -> list[dict[str, Any]]:
        """Rank services by average resilience score."""
        score_map = {
            ResilienceScore.EXCELLENT: 100,
            ResilienceScore.GOOD: 80,
            ResilienceScore.MODERATE: 60,
            ResilienceScore.POOR: 30,
            ResilienceScore.FAILING: 0,
        }
        svc_scores: dict[str, list[int]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service_id, []).append(score_map.get(r.resilience_score, 50))
        results: list[dict[str, Any]] = []
        for sid, scores in svc_scores.items():
            avg = round(sum(scores) / len(scores), 2)
            results.append(
                {
                    "service_id": sid,
                    "avg_resilience_score": avg,
                    "experiment_count": len(scores),
                }
            )
        results.sort(key=lambda x: x["avg_resilience_score"])
        return results

    def compute_recovery_time_by_type(self) -> list[dict[str, Any]]:
        """Compute average recovery time per experiment type."""
        type_times: dict[str, list[float]] = {}
        for r in self._records:
            if r.recovery_time_seconds > 0:
                type_times.setdefault(r.experiment_type.value, []).append(r.recovery_time_seconds)
        results: list[dict[str, Any]] = []
        for etype, times in type_times.items():
            avg = round(sum(times) / len(times), 2)
            results.append(
                {
                    "experiment_type": etype,
                    "avg_recovery_seconds": avg,
                    "max_recovery_seconds": round(max(times), 2),
                    "sample_count": len(times),
                }
            )
        results.sort(key=lambda x: x["avg_recovery_seconds"], reverse=True)
        return results

    def detect_blast_radius_outliers(self) -> list[dict[str, Any]]:
        """Detect experiments with unusually large blast radius."""
        if not self._records:
            return []
        radii = [r.blast_radius for r in self._records if r.blast_radius > 0]
        if not radii:
            return []
        avg = sum(radii) / len(radii)
        threshold = avg * 2.0
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.blast_radius > threshold:
                results.append(
                    {
                        "experiment_name": r.experiment_name,
                        "service_id": r.service_id,
                        "blast_radius": r.blast_radius,
                        "avg_blast_radius": round(avg, 2),
                        "experiment_type": r.experiment_type.value,
                    }
                )
        results.sort(key=lambda x: x["blast_radius"], reverse=True)
        return results
