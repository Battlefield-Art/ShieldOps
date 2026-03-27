"""Fix Velocity Analytics — remediation speed."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class VelocityMetric(StrEnum):
    TIME_TO_DETECT = "time_to_detect"
    TIME_TO_REMEDIATE = "time_to_remediate"
    TIME_TO_VERIFY = "time_to_verify"
    QUEUE_WAIT = "queue_wait"
    TOTAL_CYCLE = "total_cycle"


class StageTime(StrEnum):
    FAST = "fast"
    NORMAL = "normal"
    SLOW = "slow"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class ThroughputRate(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    STALLED = "stalled"
    RAMPING = "ramping"


# --- Models ---


class FixVelocityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    remediation_id: str = ""
    metric: VelocityMetric = VelocityMetric.TOTAL_CYCLE
    stage: StageTime = StageTime.NORMAL
    throughput: ThroughputRate = ThroughputRate.MEDIUM
    duration_sec: float = 0.0
    queue_depth: int = 0
    automated: bool = False
    created_at: float = Field(default_factory=time.time)


class FixVelocityAnalysis(BaseModel):
    remediation_id: str = ""
    total_stages: int = 0
    total_duration_sec: float = 0.0
    slowest_stage: str = ""
    throughput: str = ""
    analyzed_at: float = Field(default_factory=time.time)


class FixVelocityReport(BaseModel):
    total_records: int = 0
    avg_cycle_sec: float = 0.0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_stage: dict[str, int] = Field(default_factory=dict)
    bottleneck_stage: str = ""
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class FixVelocityAnalytics:
    """Analyze fix velocity and throughput."""

    def __init__(self, max_records: int = 10000) -> None:
        self._max = max_records
        self._records: list[FixVelocityRecord] = []
        logger.info(
            "fix_velocity_analytics.init",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> FixVelocityRecord:
        rec = FixVelocityRecord(**kwargs)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "fix_velocity.recorded",
            record_id=rec.id,
        )
        return rec

    def process(self, remediation_id: str) -> FixVelocityAnalysis:
        recs = [r for r in self._records if r.remediation_id == remediation_id]
        if not recs:
            return FixVelocityAnalysis(remediation_id=remediation_id)
        total_dur = sum(r.duration_sec for r in recs)
        slowest = max(recs, key=lambda r: r.duration_sec)
        tps = {
            ThroughputRate.HIGH: 4,
            ThroughputRate.MEDIUM: 3,
            ThroughputRate.LOW: 2,
            ThroughputRate.STALLED: 1,
            ThroughputRate.RAMPING: 3,
        }
        avg_tp = sum(tps[r.throughput] for r in recs) / len(recs)
        tp_label = "medium"
        if avg_tp >= 3.5:
            tp_label = "high"
        elif avg_tp < 2:
            tp_label = "low"
        return FixVelocityAnalysis(
            remediation_id=remediation_id,
            total_stages=len(recs),
            total_duration_sec=round(total_dur, 2),
            slowest_stage=slowest.metric.value,
            throughput=tp_label,
        )

    def generate_report(
        self,
    ) -> FixVelocityReport:
        by_metric: dict[str, int] = {}
        by_stage: dict[str, int] = {}
        stage_durations: dict[str, list[float]] = {}
        for r in self._records:
            m = r.metric.value
            by_metric[m] = by_metric.get(m, 0) + 1
            s = r.stage.value
            by_stage[s] = by_stage.get(s, 0) + 1
            stage_durations.setdefault(m, []).append(r.duration_sec)
        total = len(self._records)
        durations = [r.duration_sec for r in self._records if r.duration_sec > 0]
        avg_cycle = round(sum(durations) / len(durations), 2) if durations else 0.0
        bottleneck = ""
        if stage_durations:
            avgs = {k: sum(v) / len(v) for k, v in stage_durations.items() if v}
            if avgs:
                bottleneck = max(avgs, key=avgs.get)
        recs: list[str] = []
        blocked = by_stage.get("blocked", 0)
        if blocked > 0:
            recs.append(f"{blocked} blocked stage(s)")
        if bottleneck:
            recs.append(f"Bottleneck: {bottleneck}")
        if not recs:
            recs.append("Fix velocity healthy")
        return FixVelocityReport(
            total_records=total,
            avg_cycle_sec=avg_cycle,
            by_metric=by_metric,
            by_stage=by_stage,
            bottleneck_stage=bottleneck,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max,
            "unique_remediations": len({r.remediation_id for r in self._records}),
        }

    def clear_data(self) -> None:
        self._records.clear()
        logger.info("fix_velocity_analytics.cleared")

    # -- domain methods --

    def measure_velocity(
        self,
        metric: VelocityMetric | None = None,
    ) -> dict[str, Any]:
        """Measure fix velocity."""
        recs = self._records
        if metric:
            recs = [r for r in recs if r.metric == metric]
        durations = [r.duration_sec for r in recs if r.duration_sec > 0]
        avg = round(sum(durations) / len(durations), 2) if durations else 0.0
        automated = sum(1 for r in recs if r.automated)
        return {
            "metric": (metric.value if metric else "all"),
            "count": len(recs),
            "avg_duration_sec": avg,
            "automated_count": automated,
            "automation_pct": (round(automated / len(recs) * 100, 2) if recs else 0.0),
        }

    def identify_slowdowns(
        self,
        threshold_sec: float = 3600.0,
    ) -> list[dict[str, Any]]:
        """Find stages exceeding threshold."""
        return [
            {
                "record_id": r.id,
                "remediation_id": (r.remediation_id),
                "metric": r.metric.value,
                "duration_sec": r.duration_sec,
                "excess_sec": round(
                    r.duration_sec - threshold_sec,
                    2,
                ),
            }
            for r in self._records
            if r.duration_sec > threshold_sec
        ]

    def forecast_completion(self, queue_size: int = 0) -> dict[str, Any]:
        """Forecast completion time for queue."""
        durations = [r.duration_sec for r in self._records if r.duration_sec > 0]
        avg = sum(durations) / len(durations) if durations else 0.0
        est_sec = avg * queue_size
        return {
            "queue_size": queue_size,
            "avg_fix_sec": round(avg, 2),
            "estimated_total_sec": round(est_sec, 2),
            "estimated_hours": round(est_sec / 3600, 2),
        }
