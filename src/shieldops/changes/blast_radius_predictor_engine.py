"""Blast Radius Predictor Engine — predict and track deployment blast radius accuracy."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PredictionAccuracy(StrEnum):
    EXACT = "exact"
    CLOSE = "close"
    UNDERESTIMATED = "underestimated"
    OVERESTIMATED = "overestimated"
    MISSED = "missed"


class ImpactScope(StrEnum):
    SINGLE_SERVICE = "single_service"
    MULTI_SERVICE = "multi_service"
    CLUSTER_WIDE = "cluster_wide"
    REGION_WIDE = "region_wide"
    GLOBAL = "global"


class RecoverySpeed(StrEnum):
    INSTANT = "instant"
    FAST = "fast"
    MODERATE = "moderate"
    SLOW = "slow"
    MANUAL = "manual"


# --- Models ---


class BlastRadiusPredictorRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    deployment_id: str = ""
    prediction_accuracy: PredictionAccuracy = PredictionAccuracy.EXACT
    impact_scope: ImpactScope = ImpactScope.SINGLE_SERVICE
    recovery_speed: RecoverySpeed = RecoverySpeed.FAST
    predicted_services: int = 0
    actual_services: int = 0
    recovery_time_min: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class BlastRadiusPredictorAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    prediction_accuracy: PredictionAccuracy = PredictionAccuracy.EXACT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class BlastRadiusPredictorReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_prediction_accuracy: dict[str, int] = Field(default_factory=dict)
    by_impact_scope: dict[str, int] = Field(default_factory=dict)
    by_recovery_speed: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class BlastRadiusPredictorEngine:
    """Blast Radius Predictor Engine — predict and track blast radius accuracy."""

    def __init__(
        self,
        max_records: int = 200000,
        accuracy_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = accuracy_threshold
        self._records: list[BlastRadiusPredictorRecord] = []
        self._analyses: list[BlastRadiusPredictorAnalysis] = []
        logger.info(
            "blast_radius_predictor_engine.initialized",
            max_records=max_records,
            accuracy_threshold=accuracy_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        deployment_id: str,
        prediction_accuracy: PredictionAccuracy = PredictionAccuracy.EXACT,
        impact_scope: ImpactScope = ImpactScope.SINGLE_SERVICE,
        recovery_speed: RecoverySpeed = RecoverySpeed.FAST,
        predicted_services: int = 0,
        actual_services: int = 0,
        recovery_time_min: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> BlastRadiusPredictorRecord:
        record = BlastRadiusPredictorRecord(
            deployment_id=deployment_id,
            prediction_accuracy=prediction_accuracy,
            impact_scope=impact_scope,
            recovery_speed=recovery_speed,
            predicted_services=predicted_services,
            actual_services=actual_services,
            recovery_time_min=recovery_time_min,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "blast_radius_predictor_engine.record_added",
            record_id=record.id,
            deployment_id=deployment_id,
            prediction_accuracy=prediction_accuracy.value,
            impact_scope=impact_scope.value,
        )
        return record

    def get_record(self, record_id: str) -> BlastRadiusPredictorRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        prediction_accuracy: PredictionAccuracy | None = None,
        impact_scope: ImpactScope | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[BlastRadiusPredictorRecord]:
        results = list(self._records)
        if prediction_accuracy is not None:
            results = [r for r in results if r.prediction_accuracy == prediction_accuracy]
        if impact_scope is not None:
            results = [r for r in results if r.impact_scope == impact_scope]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        prediction_accuracy: PredictionAccuracy = PredictionAccuracy.EXACT,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> BlastRadiusPredictorAnalysis:
        analysis = BlastRadiusPredictorAnalysis(
            name=name,
            prediction_accuracy=prediction_accuracy,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "blast_radius_predictor_engine.analysis_added",
            name=name,
            prediction_accuracy=prediction_accuracy.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_prediction_accuracy(self) -> dict[str, Any]:
        acc_data: dict[str, int] = {}
        for r in self._records:
            key = r.prediction_accuracy.value
            acc_data[key] = acc_data.get(key, 0) + 1
        total = len(self._records) or 1
        result: dict[str, Any] = {}
        for k, count in acc_data.items():
            result[k] = {
                "count": count,
                "pct": round(count / total * 100, 2),
            }
        return result

    def identify_underestimated_blasts(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.prediction_accuracy in (
                PredictionAccuracy.UNDERESTIMATED,
                PredictionAccuracy.MISSED,
            ):
                results.append(
                    {
                        "record_id": r.id,
                        "deployment_id": r.deployment_id,
                        "prediction_accuracy": r.prediction_accuracy.value,
                        "impact_scope": r.impact_scope.value,
                        "predicted_services": r.predicted_services,
                        "actual_services": r.actual_services,
                        "recovery_time_min": r.recovery_time_min,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["actual_services"] - x["predicted_services"],
            reverse=True,
        )

    def detect_prediction_trends(self) -> dict[str, Any]:
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [a.analysis_score for a in self._analyses]
        mid = len(vals) // 2
        first_half = vals[:mid]
        second_half = vals[mid:]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        delta = round(avg_second - avg_first, 2)
        if abs(delta) < 5.0:
            trend = "stable"
        elif delta > 0:
            trend = "improving"
        else:
            trend = "degrading"
        return {
            "trend": trend,
            "delta": delta,
            "avg_first_half": round(avg_first, 2),
            "avg_second_half": round(avg_second, 2),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> BlastRadiusPredictorReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.prediction_accuracy.value] = by_e1.get(r.prediction_accuracy.value, 0) + 1
            by_e2[r.impact_scope.value] = by_e2.get(r.impact_scope.value, 0) + 1
            by_e3[r.recovery_speed.value] = by_e3.get(r.recovery_speed.value, 0) + 1
        accurate_count = sum(
            1
            for r in self._records
            if r.prediction_accuracy in (PredictionAccuracy.EXACT, PredictionAccuracy.CLOSE)
        )
        accuracy_pct = round(accurate_count / len(self._records) * 100, 2) if self._records else 0.0
        gap_count = sum(
            1
            for r in self._records
            if r.prediction_accuracy
            in (PredictionAccuracy.UNDERESTIMATED, PredictionAccuracy.MISSED)
        )
        gap_list = self.identify_underestimated_blasts()
        top_gaps = [g["deployment_id"] for g in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} underestimated/missed blast prediction(s)")
        if self._records and accuracy_pct < self._threshold:
            recs.append(f"Prediction accuracy {accuracy_pct}% below threshold ({self._threshold}%)")
        if not recs:
            recs.append("Blast Radius Predictor Engine is healthy")
        return BlastRadiusPredictorReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=accuracy_pct,
            by_prediction_accuracy=by_e1,
            by_impact_scope=by_e2,
            by_recovery_speed=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("blast_radius_predictor_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.prediction_accuracy.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "accuracy_threshold": self._threshold,
            "prediction_accuracy_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
