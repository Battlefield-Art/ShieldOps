"""OTelCollectorAutoscalerEngine — auto-scale OTel collectors based on telemetry volume,
queue depth, and resource utilization."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ScaleDirection(StrEnum):
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    MAINTAIN = "maintain"
    EMERGENCY_SCALE = "emergency_scale"


class ScalingMetric(StrEnum):
    TELEMETRY_VOLUME = "telemetry_volume"
    QUEUE_DEPTH = "queue_depth"
    CPU_UTILIZATION = "cpu_utilization"
    MEMORY_UTILIZATION = "memory_utilization"


class ScalerStatus(StrEnum):
    IDLE = "idle"
    SCALING = "scaling"
    COOLDOWN = "cooldown"
    ERROR = "error"


# --- Models ---


class CollectorAutoscalerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    collector_id: str = ""
    scale_direction: ScaleDirection = ScaleDirection.MAINTAIN
    scaling_metric: ScalingMetric = ScalingMetric.TELEMETRY_VOLUME
    scaler_status: ScalerStatus = ScalerStatus.IDLE
    value: float = 0.0
    threshold: float = 0.0
    replica_count: int = 1
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CollectorAutoscalerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    collector_id: str = ""
    avg_value: float = 0.0
    max_value: float = 0.0
    breach_count: int = 0
    recommended_direction: ScaleDirection = ScaleDirection.MAINTAIN
    recommended_replicas: int = 1
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CollectorAutoscalerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_utilization: float = 0.0
    by_scale_direction: dict[str, int] = Field(default_factory=dict)
    by_scaling_metric: dict[str, int] = Field(default_factory=dict)
    by_scaler_status: dict[str, int] = Field(default_factory=dict)
    collectors_needing_scale: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OTelCollectorAutoscalerEngine:
    """Auto-scale OTel collectors based on telemetry volume, queue depth,
    and resource utilization."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[CollectorAutoscalerRecord] = []
        self._analyses: list[CollectorAutoscalerAnalysis] = []
        logger.info(
            "otel.collector.autoscaler.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        collector_id: str,
        scale_direction: ScaleDirection = ScaleDirection.MAINTAIN,
        scaling_metric: ScalingMetric = ScalingMetric.TELEMETRY_VOLUME,
        scaler_status: ScalerStatus = ScalerStatus.IDLE,
        value: float = 0.0,
        threshold: float = 0.0,
        replica_count: int = 1,
        service: str = "",
        team: str = "",
    ) -> CollectorAutoscalerRecord:
        record = CollectorAutoscalerRecord(
            collector_id=collector_id,
            scale_direction=scale_direction,
            scaling_metric=scaling_metric,
            scaler_status=scaler_status,
            value=value,
            threshold=threshold,
            replica_count=replica_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel.collector.autoscaler.record_added",
            record_id=record.id,
            collector_id=collector_id,
            scaling_metric=scaling_metric.value,
        )
        return record

    def get_record(self, record_id: str) -> CollectorAutoscalerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        collector_id: str | None = None,
        scaling_metric: ScalingMetric | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CollectorAutoscalerRecord]:
        results = list(self._records)
        if collector_id is not None:
            results = [r for r in results if r.collector_id == collector_id]
        if scaling_metric is not None:
            results = [r for r in results if r.scaling_metric == scaling_metric]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def process(self, collector_id: str) -> CollectorAutoscalerAnalysis | None:
        records = [r for r in self._records if r.collector_id == collector_id]
        if not records:
            return None
        values = [r.value for r in records]
        thresholds = [r.threshold for r in records if r.threshold > 0]
        avg_val = round(sum(values) / len(values), 2)
        max_val = max(values)
        breach_count = sum(1 for r in records if r.threshold > 0 and r.value > r.threshold)
        breach_ratio = breach_count / len(records) if records else 0.0
        if breach_ratio > 0.75:
            direction = ScaleDirection.EMERGENCY_SCALE
        elif breach_ratio > 0.5:
            direction = ScaleDirection.SCALE_UP
        elif avg_val < self._threshold * 0.3 and len(records) > 2:
            direction = ScaleDirection.SCALE_DOWN
        else:
            direction = ScaleDirection.MAINTAIN
        avg_threshold = sum(thresholds) / len(thresholds) if thresholds else self._threshold
        recommended_replicas = max(1, round(max_val / avg_threshold)) if avg_threshold > 0 else 1
        analysis = CollectorAutoscalerAnalysis(
            collector_id=collector_id,
            avg_value=avg_val,
            max_value=max_val,
            breach_count=breach_count,
            recommended_direction=direction,
            recommended_replicas=recommended_replicas,
            description=f"{direction.value} for {collector_id}: avg={avg_val}, max={max_val}",
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "otel.collector.autoscaler.processed",
            collector_id=collector_id,
            direction=direction.value,
            recommended_replicas=recommended_replicas,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_scaling_recommendation(self, collector_id: str) -> dict[str, Any]:
        """Recommend scale direction based on metrics for a collector."""
        records = [r for r in self._records if r.collector_id == collector_id]
        if not records:
            return {"collector_id": collector_id, "status": "no_data"}
        values = [r.value for r in records]
        avg_val = round(sum(values) / len(values), 2)
        max_val = max(values)
        breach_count = sum(1 for r in records if r.threshold > 0 and r.value > r.threshold)
        breach_ratio = breach_count / len(records)
        if breach_ratio > 0.75:
            direction = ScaleDirection.EMERGENCY_SCALE
        elif breach_ratio > 0.5:
            direction = ScaleDirection.SCALE_UP
        elif avg_val < self._threshold * 0.3:
            direction = ScaleDirection.SCALE_DOWN
        else:
            direction = ScaleDirection.MAINTAIN
        return {
            "collector_id": collector_id,
            "direction": direction.value,
            "avg_value": avg_val,
            "max_value": max_val,
            "breach_count": breach_count,
            "breach_ratio": round(breach_ratio, 2),
            "record_count": len(records),
        }

    def detect_traffic_spikes(self) -> list[dict[str, Any]]:
        """Detect sudden volume increases that need emergency scaling."""
        by_collector: dict[str, list[CollectorAutoscalerRecord]] = {}
        for r in self._records:
            by_collector.setdefault(r.collector_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, recs in by_collector.items():
            if len(recs) < 3:
                continue
            sorted_recs = sorted(recs, key=lambda x: x.created_at)
            mid = len(sorted_recs) // 2
            older_avg = sum(r.value for r in sorted_recs[:mid]) / mid
            recent_avg = sum(r.value for r in sorted_recs[mid:]) / (len(sorted_recs) - mid)
            if older_avg > 0:
                spike_ratio = recent_avg / older_avg
            else:
                spike_ratio = recent_avg if recent_avg > 0 else 0.0
            if spike_ratio > 2.0:
                results.append(
                    {
                        "collector_id": cid,
                        "spike_ratio": round(spike_ratio, 2),
                        "older_avg": round(older_avg, 2),
                        "recent_avg": round(recent_avg, 2),
                        "needs_emergency_scale": spike_ratio > 5.0,
                    }
                )
        results.sort(key=lambda x: x["spike_ratio"], reverse=True)
        return results

    def optimize_replica_count(self) -> list[dict[str, Any]]:
        """Compute optimal replica count across all collectors."""
        by_collector: dict[str, list[CollectorAutoscalerRecord]] = {}
        for r in self._records:
            by_collector.setdefault(r.collector_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, recs in by_collector.items():
            values = [r.value for r in recs]
            avg_val = sum(values) / len(values)
            max_val = max(values)
            current_replicas = recs[-1].replica_count
            optimal = max(1, round(max_val / self._threshold)) if self._threshold > 0 else 1
            results.append(
                {
                    "collector_id": cid,
                    "current_replicas": current_replicas,
                    "optimal_replicas": optimal,
                    "avg_value": round(avg_val, 2),
                    "max_value": round(max_val, 2),
                    "needs_adjustment": current_replicas != optimal,
                }
            )
        results.sort(
            key=lambda x: abs(x["current_replicas"] - x["optimal_replicas"]),
            reverse=True,
        )
        return results

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> CollectorAutoscalerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.scale_direction.value] = by_e1.get(r.scale_direction.value, 0) + 1
            by_e2[r.scaling_metric.value] = by_e2.get(r.scaling_metric.value, 0) + 1
            by_e3[r.scaler_status.value] = by_e3.get(r.scaler_status.value, 0) + 1
        values = [r.value for r in self._records]
        avg_util = round(sum(values) / len(values), 2) if values else 0.0
        needing_scale: list[str] = []
        by_collector: dict[str, list[float]] = {}
        for r in self._records:
            by_collector.setdefault(r.collector_id, []).append(r.value)
        for cid, vals in by_collector.items():
            if max(vals) > self._threshold:
                needing_scale.append(cid)
        recs: list[str] = []
        if needing_scale:
            recs.append(f"{len(needing_scale)} collector(s) exceed threshold ({self._threshold})")
        if avg_util > self._threshold and self._records:
            recs.append(f"Avg utilization {avg_util} exceeds threshold ({self._threshold})")
        if not recs:
            recs.append("OTel collector autoscaler is healthy")
        return CollectorAutoscalerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_utilization=avg_util,
            by_scale_direction=by_e1,
            by_scaling_metric=by_e2,
            by_scaler_status=by_e3,
            collectors_needing_scale=needing_scale,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel.collector.autoscaler.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        metric_dist: dict[str, int] = {}
        for r in self._records:
            key = r.scaling_metric.value
            metric_dist[key] = metric_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "scaling_metric_distribution": metric_dist,
            "unique_collectors": len({r.collector_id for r in self._records}),
            "unique_teams": len({r.team for r in self._records}),
        }
