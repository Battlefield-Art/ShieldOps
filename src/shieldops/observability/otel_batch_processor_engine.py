"""OtelBatchProcessorEngine — Monitor and tune OTel batch processor performance."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BatchStatus(StrEnum):
    HEALTHY = "healthy"
    FULL = "full"
    DROPPING = "dropping"
    STALLED = "stalled"


class QueuePressure(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class TuningAction(StrEnum):
    INCREASE_BATCH_SIZE = "increase_batch_size"
    DECREASE_TIMEOUT = "decrease_timeout"
    ADD_MEMORY = "add_memory"
    SCALE_OUT = "scale_out"


# --- Models ---


class OtelBatchProcessorRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    batch_status: BatchStatus = BatchStatus.HEALTHY
    queue_pressure: QueuePressure = QueuePressure.LOW
    tuning_action: TuningAction = TuningAction.INCREASE_BATCH_SIZE
    score: float = 0.0
    batch_size: int = 512
    queue_depth: int = 0
    queue_capacity: int = 2048
    dropped_spans: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelBatchProcessorAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    batch_status: BatchStatus = BatchStatus.HEALTHY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelBatchProcessorReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_batch_status: dict[str, int] = Field(default_factory=dict)
    by_queue_pressure: dict[str, int] = Field(default_factory=dict)
    by_tuning_action: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OtelBatchProcessorEngine:
    """Monitor and tune OTel batch processor performance engine."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[OtelBatchProcessorRecord] = []
        self._analyses: list[OtelBatchProcessorAnalysis] = []
        logger.info(
            "otel_batch_processor_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        batch_status: BatchStatus = BatchStatus.HEALTHY,
        queue_pressure: QueuePressure = QueuePressure.LOW,
        tuning_action: TuningAction = TuningAction.INCREASE_BATCH_SIZE,
        score: float = 0.0,
        batch_size: int = 512,
        queue_depth: int = 0,
        queue_capacity: int = 2048,
        dropped_spans: int = 0,
        service: str = "",
        team: str = "",
    ) -> OtelBatchProcessorRecord:
        record = OtelBatchProcessorRecord(
            name=name,
            batch_status=batch_status,
            queue_pressure=queue_pressure,
            tuning_action=tuning_action,
            score=score,
            batch_size=batch_size,
            queue_depth=queue_depth,
            queue_capacity=queue_capacity,
            dropped_spans=dropped_spans,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel_batch_processor_engine.record_added",
            record_id=record.id,
            name=name,
            batch_status=batch_status.value,
            queue_pressure=queue_pressure.value,
        )
        return record

    def get_record(self, record_id: str) -> OtelBatchProcessorRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        batch_status: BatchStatus | None = None,
        queue_pressure: QueuePressure | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[OtelBatchProcessorRecord]:
        results = list(self._records)
        if batch_status is not None:
            results = [r for r in results if r.batch_status == batch_status]
        if queue_pressure is not None:
            results = [r for r in results if r.queue_pressure == queue_pressure]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        batch_status: BatchStatus = BatchStatus.HEALTHY,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> OtelBatchProcessorAnalysis:
        analysis = OtelBatchProcessorAnalysis(
            name=name,
            batch_status=batch_status,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "otel_batch_processor_engine.analysis_added",
            name=name,
            batch_status=batch_status.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def detect_batch_pressure(self) -> list[dict[str, Any]]:
        """Detect processors under batch pressure."""
        svc_data: dict[str, list[OtelBatchProcessorRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        pressure_results: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            high_pressure = sum(
                1
                for r in records
                if r.queue_pressure in (QueuePressure.HIGH, QueuePressure.CRITICAL)
            )
            total_dropped = sum(r.dropped_spans for r in records)
            avg_queue_util = 0.0
            for r in records:
                if r.queue_capacity > 0:
                    avg_queue_util += r.queue_depth / r.queue_capacity
            avg_queue_util = round(avg_queue_util / len(records), 4) if records else 0.0
            if high_pressure > 0 or total_dropped > 0:
                pressure_results.append(
                    {
                        "service": svc,
                        "high_pressure_count": high_pressure,
                        "total_dropped_spans": total_dropped,
                        "avg_queue_utilization": avg_queue_util,
                        "total_records": len(records),
                        "severity": "critical" if avg_queue_util > 0.9 else "warning",
                    }
                )
        return sorted(pressure_results, key=lambda x: x["avg_queue_utilization"], reverse=True)

    def compute_optimal_batch_config(self) -> list[dict[str, Any]]:
        """Compute optimal batch configuration per service."""
        svc_data: dict[str, list[OtelBatchProcessorRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        configs: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            avg_batch_size = round(sum(r.batch_size for r in records) / len(records))
            avg_queue_depth = round(sum(r.queue_depth for r in records) / len(records))
            dropping = sum(1 for r in records if r.batch_status == BatchStatus.DROPPING)
            recommended_batch = avg_batch_size
            if dropping > 0:
                recommended_batch = min(avg_batch_size * 2, 8192)
            recommended_capacity = max(avg_queue_depth * 4, records[0].queue_capacity)
            configs.append(
                {
                    "service": svc,
                    "current_avg_batch_size": avg_batch_size,
                    "recommended_batch_size": recommended_batch,
                    "current_avg_queue_depth": avg_queue_depth,
                    "recommended_queue_capacity": recommended_capacity,
                    "dropping_count": dropping,
                }
            )
        return sorted(configs, key=lambda x: x["dropping_count"], reverse=True)

    def predict_queue_overflow(self) -> list[dict[str, Any]]:
        """Predict which queues are likely to overflow soon."""
        predictions: list[dict[str, Any]] = []
        svc_data: dict[str, list[OtelBatchProcessorRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        for svc, records in svc_data.items():
            if not records:
                continue
            latest = records[-1]
            utilization = (
                round(latest.queue_depth / latest.queue_capacity, 4)
                if latest.queue_capacity > 0
                else 0.0
            )
            risk = "low"
            if utilization > 0.9:
                risk = "critical"
            elif utilization > 0.75:
                risk = "high"
            elif utilization > 0.5:
                risk = "medium"
            if risk != "low":
                predictions.append(
                    {
                        "service": svc,
                        "current_utilization": utilization,
                        "queue_depth": latest.queue_depth,
                        "queue_capacity": latest.queue_capacity,
                        "overflow_risk": risk,
                        "recommendation": (
                            "scale_out" if risk == "critical" else "increase_capacity"
                        ),
                    }
                )
        return sorted(
            predictions,
            key=lambda x: x["current_utilization"],
            reverse=True,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.batch_status.value
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
                        "batch_status": r.batch_status.value,
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

    def generate_report(self) -> OtelBatchProcessorReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.batch_status.value] = by_e1.get(r.batch_status.value, 0) + 1
            by_e2[r.queue_pressure.value] = by_e2.get(r.queue_pressure.value, 0) + 1
            by_e3[r.tuning_action.value] = by_e3.get(r.tuning_action.value, 0) + 1
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
            recs.append("OTel Batch Processor Engine is healthy")
        return OtelBatchProcessorReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_batch_status=by_e1,
            by_queue_pressure=by_e2,
            by_tuning_action=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel_batch_processor_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.batch_status.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "batch_status_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
