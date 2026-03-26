"""Capacity Forecast Engine — track resource capacity forecasting accuracy."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ForecastMethod(StrEnum):
    STATISTICAL = "statistical"
    ML_MODEL = "ml_model"
    HEURISTIC = "heuristic"
    MANUAL = "manual"
    HYBRID = "hybrid"


class ResourceCategory(StrEnum):
    COMPUTE = "compute"
    MEMORY = "memory"
    STORAGE = "storage"
    NETWORK = "network"
    DATABASE = "database"


class ForecastAccuracy(StrEnum):
    EXACT = "exact"
    CLOSE = "close"
    OVERESTIMATED = "overestimated"
    UNDERESTIMATED = "underestimated"
    MISSED = "missed"


# --- Models ---


class CapacityForecastRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    forecast_method: ForecastMethod = ForecastMethod.STATISTICAL
    resource_category: ResourceCategory = ResourceCategory.COMPUTE
    forecast_accuracy: ForecastAccuracy = ForecastAccuracy.CLOSE
    predicted_value: float = 0.0
    actual_value: float = 0.0
    deviation_pct: float = 0.0
    horizon_days: int = 30
    confidence_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CapacityForecastAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    analysis_score: float = 0.0
    forecast_method: ForecastMethod = ForecastMethod.STATISTICAL
    mean_deviation: float = 0.0
    data_points: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CapacityForecastReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_accuracy_pct: float = 0.0
    by_method: dict[str, int] = Field(default_factory=dict)
    by_resource: dict[str, int] = Field(default_factory=dict)
    by_accuracy: dict[str, int] = Field(default_factory=dict)
    low_accuracy_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class CapacityForecastEngine:
    """Track resource capacity forecasting accuracy across services."""

    def __init__(
        self,
        max_records: int = 200000,
        accuracy_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._accuracy_threshold = accuracy_threshold
        self._records: list[CapacityForecastRecord] = []
        self._analyses: dict[str, CapacityForecastAnalysis] = {}
        logger.info(
            "capacity_forecast_engine.init",
            max_records=max_records,
            accuracy_threshold=accuracy_threshold,
        )

    def add_record(
        self,
        service_id: str = "",
        forecast_method: ForecastMethod = ForecastMethod.STATISTICAL,
        resource_category: ResourceCategory = ResourceCategory.COMPUTE,
        forecast_accuracy: ForecastAccuracy = ForecastAccuracy.CLOSE,
        predicted_value: float = 0.0,
        actual_value: float = 0.0,
        deviation_pct: float = 0.0,
        horizon_days: int = 30,
        confidence_score: float = 0.0,
        description: str = "",
    ) -> CapacityForecastRecord:
        record = CapacityForecastRecord(
            service_id=service_id,
            forecast_method=forecast_method,
            resource_category=resource_category,
            forecast_accuracy=forecast_accuracy,
            predicted_value=predicted_value,
            actual_value=actual_value,
            deviation_pct=deviation_pct,
            horizon_days=horizon_days,
            confidence_score=confidence_score,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "capacity_forecast_engine.record_added",
            record_id=record.id,
            service_id=service_id,
        )
        return record

    def process(self, key: str) -> CapacityForecastAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        points = sum(1 for r in self._records if r.service_id == rec.service_id)
        devs = [
            r.deviation_pct
            for r in self._records
            if r.service_id == rec.service_id
        ]
        mean_dev = round(sum(devs) / len(devs), 2) if devs else 0.0
        score = round(max(0.0, 100.0 - mean_dev), 2)
        analysis = CapacityForecastAnalysis(
            service_id=rec.service_id,
            analysis_score=score,
            forecast_method=rec.forecast_method,
            mean_deviation=mean_dev,
            data_points=points,
            description=f"Forecast accuracy {score}% for {rec.service_id}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> CapacityForecastReport:
        by_m: dict[str, int] = {}
        by_r: dict[str, int] = {}
        by_a: dict[str, int] = {}
        devs: list[float] = []
        for r in self._records:
            by_m[r.forecast_method.value] = (
                by_m.get(r.forecast_method.value, 0) + 1
            )
            by_r[r.resource_category.value] = (
                by_r.get(r.resource_category.value, 0) + 1
            )
            by_a[r.forecast_accuracy.value] = (
                by_a.get(r.forecast_accuracy.value, 0) + 1
            )
            devs.append(r.deviation_pct)
        avg_acc = round(
            100.0 - (sum(devs) / len(devs)) if devs else 0.0, 2
        )
        low = list(
            {
                r.service_id
                for r in self._records
                if r.forecast_accuracy
                in (ForecastAccuracy.MISSED, ForecastAccuracy.UNDERESTIMATED)
            }
        )[:10]
        recs: list[str] = []
        if avg_acc < self._accuracy_threshold:
            recs.append(
                f"Average accuracy {avg_acc}% below threshold"
                f" {self._accuracy_threshold}% — retrain models"
            )
        if low:
            recs.append(f"{len(low)} services with low forecast accuracy")
        if not recs:
            recs.append(
                "Capacity forecasting accuracy within acceptable range"
            )
        return CapacityForecastReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_accuracy_pct=avg_acc,
            by_method=by_m,
            by_resource=by_r,
            by_accuracy=by_a,
            low_accuracy_services=low,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        method_dist: dict[str, int] = {}
        for r in self._records:
            k = r.forecast_method.value
            method_dist[k] = method_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "accuracy_threshold": self._accuracy_threshold,
            "method_distribution": method_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("capacity_forecast_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def rank_methods_by_accuracy(self) -> list[dict[str, Any]]:
        """Rank forecast methods by average accuracy."""
        method_devs: dict[str, list[float]] = {}
        for r in self._records:
            method_devs.setdefault(r.forecast_method.value, []).append(
                r.deviation_pct
            )
        results: list[dict[str, Any]] = []
        for method, devs in method_devs.items():
            avg_dev = round(sum(devs) / len(devs), 2)
            results.append(
                {
                    "method": method,
                    "avg_deviation_pct": avg_dev,
                    "accuracy_pct": round(100.0 - avg_dev, 2),
                    "sample_count": len(devs),
                }
            )
        results.sort(key=lambda x: x["accuracy_pct"], reverse=True)
        return results

    def detect_forecast_drift(self) -> list[dict[str, Any]]:
        """Detect services where forecast accuracy is degrading."""
        svc_records: dict[str, list[CapacityForecastRecord]] = {}
        for r in self._records:
            svc_records.setdefault(r.service_id, []).append(r)
        results: list[dict[str, Any]] = []
        for sid, recs in svc_records.items():
            if len(recs) < 4:
                continue
            mid = len(recs) // 2
            first_avg = sum(r.deviation_pct for r in recs[:mid]) / mid
            second_avg = (
                sum(r.deviation_pct for r in recs[mid:]) / len(recs[mid:])
            )
            delta = round(second_avg - first_avg, 2)
            if delta > 5.0:
                results.append(
                    {
                        "service_id": sid,
                        "early_deviation": round(first_avg, 2),
                        "recent_deviation": round(second_avg, 2),
                        "drift_delta": delta,
                    }
                )
        results.sort(key=lambda x: x["drift_delta"], reverse=True)
        return results

    def summarize_by_resource_category(self) -> list[dict[str, Any]]:
        """Summarize forecast performance per resource category."""
        cat_data: dict[str, list[float]] = {}
        cat_counts: dict[str, int] = {}
        for r in self._records:
            k = r.resource_category.value
            cat_data.setdefault(k, []).append(r.deviation_pct)
            cat_counts[k] = cat_counts.get(k, 0) + 1
        results: list[dict[str, Any]] = []
        for cat, devs in cat_data.items():
            avg = round(sum(devs) / len(devs), 2) if devs else 0.0
            results.append(
                {
                    "resource_category": cat,
                    "avg_deviation_pct": avg,
                    "accuracy_pct": round(100.0 - avg, 2),
                    "record_count": cat_counts[cat],
                }
            )
        results.sort(key=lambda x: x["accuracy_pct"], reverse=True)
        return results
