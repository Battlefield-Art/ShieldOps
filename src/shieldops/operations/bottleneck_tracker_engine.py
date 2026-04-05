"""Bottleneck Tracker Engine — track resource bottleneck detection and resolution."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BottleneckType(StrEnum):
    CPU = "cpu"
    MEMORY = "memory"
    DISK_IO = "disk_io"
    NETWORK = "network"
    CONNECTION_POOL = "connection_pool"


class ResolutionStatus(StrEnum):
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    RECURRING = "recurring"


class ImpactLevel(StrEnum):
    SERVICE_DOWN = "service_down"
    DEGRADED = "degraded"
    SLOW = "slow"
    MINOR = "minor"
    NONE = "none"


# --- Models ---


class BottleneckTrackerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    bottleneck_type: BottleneckType = BottleneckType.CPU
    resolution_status: ResolutionStatus = ResolutionStatus.DETECTED
    impact_level: ImpactLevel = ImpactLevel.MINOR
    utilization_pct: float = 0.0
    duration_seconds: float = 0.0
    affected_requests: int = 0
    resolution_time_seconds: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class BottleneckTrackerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    analysis_score: float = 0.0
    bottleneck_type: BottleneckType = BottleneckType.CPU
    recurring: bool = False
    data_points: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class BottleneckTrackerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_resolution_time: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_impact: dict[str, int] = Field(default_factory=dict)
    high_impact_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class BottleneckTrackerEngine:
    """Track resource bottleneck detection and resolution across services."""

    def __init__(
        self,
        max_records: int = 200000,
        severity_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._severity_threshold = severity_threshold
        self._records: list[BottleneckTrackerRecord] = []
        self._analyses: dict[str, BottleneckTrackerAnalysis] = {}
        logger.info(
            "bottleneck_tracker_engine.init",
            max_records=max_records,
            severity_threshold=severity_threshold,
        )

    def add_record(
        self,
        service_id: str = "",
        bottleneck_type: BottleneckType = BottleneckType.CPU,
        resolution_status: ResolutionStatus = ResolutionStatus.DETECTED,
        impact_level: ImpactLevel = ImpactLevel.MINOR,
        utilization_pct: float = 0.0,
        duration_seconds: float = 0.0,
        affected_requests: int = 0,
        resolution_time_seconds: float = 0.0,
        description: str = "",
    ) -> BottleneckTrackerRecord:
        record = BottleneckTrackerRecord(
            service_id=service_id,
            bottleneck_type=bottleneck_type,
            resolution_status=resolution_status,
            impact_level=impact_level,
            utilization_pct=utilization_pct,
            duration_seconds=duration_seconds,
            affected_requests=affected_requests,
            resolution_time_seconds=resolution_time_seconds,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "bottleneck_tracker_engine.record_added",
            record_id=record.id,
            service_id=service_id,
        )
        return record

    def process(self, key: str) -> BottleneckTrackerAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        points = sum(1 for r in self._records if r.service_id == rec.service_id)
        recurring = rec.resolution_status == ResolutionStatus.RECURRING
        impact_weight = {
            ImpactLevel.SERVICE_DOWN: 100,
            ImpactLevel.DEGRADED: 75,
            ImpactLevel.SLOW: 50,
            ImpactLevel.MINOR: 25,
            ImpactLevel.NONE: 0,
        }
        score = round(
            impact_weight.get(rec.impact_level, 0) * (rec.utilization_pct / 100.0),
            2,
        )
        analysis = BottleneckTrackerAnalysis(
            service_id=rec.service_id,
            analysis_score=score,
            bottleneck_type=rec.bottleneck_type,
            recurring=recurring,
            data_points=points,
            description=(
                f"Bottleneck {rec.bottleneck_type.value} on"
                f" {rec.service_id} — impact {rec.impact_level.value}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> BottleneckTrackerReport:
        by_t: dict[str, int] = {}
        by_s: dict[str, int] = {}
        by_i: dict[str, int] = {}
        res_times: list[float] = []
        for r in self._records:
            by_t[r.bottleneck_type.value] = by_t.get(r.bottleneck_type.value, 0) + 1
            by_s[r.resolution_status.value] = by_s.get(r.resolution_status.value, 0) + 1
            by_i[r.impact_level.value] = by_i.get(r.impact_level.value, 0) + 1
            if r.resolution_time_seconds > 0:
                res_times.append(r.resolution_time_seconds)
        avg_res = round(sum(res_times) / len(res_times), 2) if res_times else 0.0
        high = list(
            {
                r.service_id
                for r in self._records
                if r.impact_level in (ImpactLevel.SERVICE_DOWN, ImpactLevel.DEGRADED)
            }
        )[:10]
        recs: list[str] = []
        if high:
            recs.append(f"{len(high)} services with high-impact bottlenecks")
        recurring_count = sum(
            1 for r in self._records if r.resolution_status == ResolutionStatus.RECURRING
        )
        if recurring_count:
            recs.append(f"{recurring_count} recurring bottlenecks — investigate root cause")
        if not recs:
            recs.append("Bottleneck detection healthy — no critical issues")
        return BottleneckTrackerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_resolution_time=avg_res,
            by_type=by_t,
            by_status=by_s,
            by_impact=by_i,
            high_impact_services=high,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            k = r.bottleneck_type.value
            type_dist[k] = type_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "severity_threshold": self._severity_threshold,
            "type_distribution": type_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("bottleneck_tracker_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def identify_top_bottlenecks(self) -> list[dict[str, Any]]:
        """Identify top bottleneck types by frequency and impact."""
        type_data: dict[str, dict[str, Any]] = {}
        for r in self._records:
            k = r.bottleneck_type.value
            if k not in type_data:
                type_data[k] = {
                    "count": 0,
                    "total_duration": 0.0,
                    "total_affected": 0,
                }
            type_data[k]["count"] += 1
            type_data[k]["total_duration"] += r.duration_seconds
            type_data[k]["total_affected"] += r.affected_requests
        results: list[dict[str, Any]] = []
        for btype, data in type_data.items():
            results.append(
                {
                    "bottleneck_type": btype,
                    "occurrence_count": data["count"],
                    "total_duration_seconds": round(data["total_duration"], 2),
                    "total_affected_requests": data["total_affected"],
                }
            )
        results.sort(key=lambda x: x["occurrence_count"], reverse=True)
        return results

    def compute_mttr_by_type(self) -> list[dict[str, Any]]:
        """Compute mean time to resolve per bottleneck type."""
        type_times: dict[str, list[float]] = {}
        for r in self._records:
            if r.resolution_time_seconds > 0:
                type_times.setdefault(r.bottleneck_type.value, []).append(r.resolution_time_seconds)
        results: list[dict[str, Any]] = []
        for btype, times in type_times.items():
            avg = round(sum(times) / len(times), 2)
            results.append(
                {
                    "bottleneck_type": btype,
                    "mttr_seconds": avg,
                    "sample_count": len(times),
                }
            )
        results.sort(key=lambda x: x["mttr_seconds"], reverse=True)
        return results

    def detect_recurring_bottlenecks(self) -> list[dict[str, Any]]:
        """Detect services with recurring bottlenecks."""
        svc_counts: dict[str, int] = {}
        svc_types: dict[str, set[str]] = {}
        for r in self._records:
            svc_counts[r.service_id] = svc_counts.get(r.service_id, 0) + 1
            svc_types.setdefault(r.service_id, set()).add(r.bottleneck_type.value)
        results: list[dict[str, Any]] = []
        for sid, count in svc_counts.items():
            if count >= 3:
                results.append(
                    {
                        "service_id": sid,
                        "bottleneck_count": count,
                        "bottleneck_types": sorted(svc_types[sid]),
                    }
                )
        results.sort(key=lambda x: x["bottleneck_count"], reverse=True)
        return results
