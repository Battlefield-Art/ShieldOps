"""OTelPipelineHealthEngine — monitor OTel collector pipeline health."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PipelineSignalType(StrEnum):
    TRACES = "traces"
    METRICS = "metrics"
    LOGS = "logs"
    PROFILES = "profiles"


class HealthIndicator(StrEnum):
    THROUGHPUT = "throughput"
    LATENCY = "latency"
    DROP_RATE = "drop_rate"
    QUEUE_DEPTH = "queue_depth"


class PipelineStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    BACKPRESSURE = "backpressure"
    FAILING = "failing"


# --- Models ---


class PipelineHealthRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    collector_id: str = ""
    signal_type: PipelineSignalType = PipelineSignalType.TRACES
    health_indicator: HealthIndicator = HealthIndicator.THROUGHPUT
    pipeline_status: PipelineStatus = PipelineStatus.HEALTHY
    value: float = 0.0
    threshold: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PipelineHealthAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    collector_id: str = ""
    signal_type: PipelineSignalType = PipelineSignalType.TRACES
    avg_value: float = 0.0
    max_value: float = 0.0
    breach_count: int = 0
    pipeline_status: PipelineStatus = PipelineStatus.HEALTHY
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PipelineHealthReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_drop_rate: float = 0.0
    by_signal_type: dict[str, int] = Field(default_factory=dict)
    by_health_indicator: dict[str, int] = Field(default_factory=dict)
    by_pipeline_status: dict[str, int] = Field(default_factory=dict)
    unhealthy_collectors: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class OTelPipelineHealthEngine:
    """Monitor OTel collector pipeline health — dropped telemetry, queue depths,
    export latency, backpressure events."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[PipelineHealthRecord] = []
        self._analyses: list[PipelineHealthAnalysis] = []
        logger.info(
            "otel.pipeline.health.engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        collector_id: str,
        signal_type: PipelineSignalType = PipelineSignalType.TRACES,
        health_indicator: HealthIndicator = HealthIndicator.THROUGHPUT,
        pipeline_status: PipelineStatus = PipelineStatus.HEALTHY,
        value: float = 0.0,
        threshold: float = 0.0,
        description: str = "",
    ) -> PipelineHealthRecord:
        record = PipelineHealthRecord(
            collector_id=collector_id,
            signal_type=signal_type,
            health_indicator=health_indicator,
            pipeline_status=pipeline_status,
            value=value,
            threshold=threshold,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel.pipeline.health.engine.record_added",
            record_id=record.id,
            collector_id=collector_id,
            signal_type=signal_type.value,
            health_indicator=health_indicator.value,
        )
        return record

    def get_record(self, record_id: str) -> PipelineHealthRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        signal_type: PipelineSignalType | None = None,
        health_indicator: HealthIndicator | None = None,
        collector_id: str | None = None,
        limit: int = 50,
    ) -> list[PipelineHealthRecord]:
        results = list(self._records)
        if signal_type is not None:
            results = [r for r in results if r.signal_type == signal_type]
        if health_indicator is not None:
            results = [r for r in results if r.health_indicator == health_indicator]
        if collector_id is not None:
            results = [r for r in results if r.collector_id == collector_id]
        return results[-limit:]

    # -- process ------------------------------------------------------------

    def process(self, key: str) -> PipelineHealthAnalysis | None:
        matched = [r for r in self._records if r.collector_id == key]
        if not matched:
            return None
        values = [r.value for r in matched]
        avg_val = round(sum(values) / len(values), 2)
        max_val = round(max(values), 2)
        breach_count = sum(1 for r in matched if r.value > r.threshold > 0)
        worst = max(matched, key=lambda r: r.value)
        if breach_count > len(matched) * 0.5:
            status = PipelineStatus.FAILING
        elif breach_count > 0:
            status = PipelineStatus.DEGRADED
        else:
            status = PipelineStatus.HEALTHY
        analysis = PipelineHealthAnalysis(
            collector_id=key,
            signal_type=worst.signal_type,
            avg_value=avg_val,
            max_value=max_val,
            breach_count=breach_count,
            pipeline_status=status,
            description=f"Analyzed {len(matched)} records for collector {key}",
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "otel.pipeline.health.engine.processed",
            collector_id=key,
            avg_value=avg_val,
            breach_count=breach_count,
            pipeline_status=status.value,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def detect_backpressure(self) -> list[dict[str, Any]]:
        """Identify collectors with queue_depth exceeding threshold."""
        results: list[dict[str, Any]] = []
        collector_data: dict[str, list[PipelineHealthRecord]] = {}
        for r in self._records:
            if r.health_indicator == HealthIndicator.QUEUE_DEPTH:
                collector_data.setdefault(r.collector_id, []).append(r)
        for cid, records in collector_data.items():
            breached = [r for r in records if r.value > r.threshold > 0]
            if breached:
                max_val = max(r.value for r in breached)
                results.append(
                    {
                        "collector_id": cid,
                        "max_queue_depth": max_val,
                        "breach_count": len(breached),
                        "status": "backpressure",
                    }
                )
        return sorted(results, key=lambda x: x["max_queue_depth"], reverse=True)

    def rank_collectors_by_health(self) -> list[dict[str, Any]]:
        """Rank collectors from worst to best health based on breach ratio."""
        collector_data: dict[str, list[PipelineHealthRecord]] = {}
        for r in self._records:
            collector_data.setdefault(r.collector_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, records in collector_data.items():
            breach_count = sum(1 for r in records if r.value > r.threshold > 0)
            health_score = round((1.0 - breach_count / len(records)) * 100 if records else 100.0, 2)
            results.append(
                {
                    "collector_id": cid,
                    "health_score": health_score,
                    "total_records": len(records),
                    "breach_count": breach_count,
                }
            )
        results.sort(key=lambda x: x["health_score"])
        return results

    def recommend_scaling(self) -> list[dict[str, Any]]:
        """Suggest scaling based on drop rates and queue depths."""
        collector_data: dict[str, list[PipelineHealthRecord]] = {}
        for r in self._records:
            collector_data.setdefault(r.collector_id, []).append(r)
        recommendations: list[dict[str, Any]] = []
        for cid, records in collector_data.items():
            drops = [r for r in records if r.health_indicator == HealthIndicator.DROP_RATE]
            queues = [r for r in records if r.health_indicator == HealthIndicator.QUEUE_DEPTH]
            avg_drop = round(sum(r.value for r in drops) / len(drops), 2) if drops else 0.0
            avg_queue = round(sum(r.value for r in queues) / len(queues), 2) if queues else 0.0
            if avg_drop > self._threshold or avg_queue > self._threshold:
                action = "scale_up"
            elif avg_drop == 0.0 and avg_queue < self._threshold * 0.2:
                action = "scale_down"
            else:
                action = "no_change"
            recommendations.append(
                {
                    "collector_id": cid,
                    "avg_drop_rate": avg_drop,
                    "avg_queue_depth": avg_queue,
                    "recommendation": action,
                }
            )
        return recommendations

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> PipelineHealthReport:
        by_signal: dict[str, int] = {}
        by_indicator: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for r in self._records:
            by_signal[r.signal_type.value] = by_signal.get(r.signal_type.value, 0) + 1
            by_indicator[r.health_indicator.value] = (
                by_indicator.get(r.health_indicator.value, 0) + 1
            )
            by_status[r.pipeline_status.value] = by_status.get(r.pipeline_status.value, 0) + 1
        drop_records = [r for r in self._records if r.health_indicator == HealthIndicator.DROP_RATE]
        avg_drop = (
            round(sum(r.value for r in drop_records) / len(drop_records), 2)
            if drop_records
            else 0.0
        )
        unhealthy = list(
            {
                r.collector_id
                for r in self._records
                if r.pipeline_status in (PipelineStatus.FAILING, PipelineStatus.BACKPRESSURE)
            }
        )
        recs: list[str] = []
        if avg_drop > self._threshold:
            recs.append(f"Avg drop rate {avg_drop} exceeds threshold ({self._threshold})")
        if unhealthy:
            recs.append(f"{len(unhealthy)} collector(s) in unhealthy state")
        if not recs:
            recs.append("OTel Pipeline Health Engine is healthy")
        return PipelineHealthReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_drop_rate=avg_drop,
            by_signal_type=by_signal,
            by_health_indicator=by_indicator,
            by_pipeline_status=by_status,
            unhealthy_collectors=unhealthy,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel.pipeline.health.engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        signal_dist: dict[str, int] = {}
        for r in self._records:
            key = r.signal_type.value
            signal_dist[key] = signal_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "signal_type_distribution": signal_dist,
            "unique_collectors": len({r.collector_id for r in self._records}),
        }
