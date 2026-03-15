"""Pipeline Backpressure Analyzer Engine —
trace backpressure source, measure queue drain rate,
simulate load shed impact."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PipelineStage(StrEnum):
    RECEIVER = "receiver"
    PROCESSOR = "processor"
    EXPORTER = "exporter"
    INTERNAL_QUEUE = "internal_queue"


class BackpressureLevel(StrEnum):
    NONE = "none"
    MILD = "mild"
    SEVERE = "severe"
    CRITICAL = "critical"


class PropagationDirection(StrEnum):
    DOWNSTREAM = "downstream"
    UPSTREAM = "upstream"
    BIDIRECTIONAL = "bidirectional"
    ISOLATED = "isolated"


# --- Models ---


class PipelineBackpressureRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_id: str = ""
    pipeline_stage: PipelineStage = PipelineStage.RECEIVER
    backpressure_level: BackpressureLevel = BackpressureLevel.NONE
    propagation_direction: PropagationDirection = PropagationDirection.ISOLATED
    queue_depth: int = 0
    queue_capacity: int = 1
    drain_rate_per_sec: float = 0.0
    fill_rate_per_sec: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PipelineBackpressureAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_id: str = ""
    pipeline_stage: PipelineStage = PipelineStage.RECEIVER
    backpressure_level: BackpressureLevel = BackpressureLevel.NONE
    queue_fill_pct: float = 0.0
    source_stage: str = ""
    drain_deficit: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PipelineBackpressureReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_queue_fill_pct: float = 0.0
    by_pipeline_stage: dict[str, int] = Field(default_factory=dict)
    by_backpressure_level: dict[str, int] = Field(default_factory=dict)
    by_propagation_direction: dict[str, int] = Field(default_factory=dict)
    critical_pipelines: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class PipelineBackpressureAnalyzerEngine:
    """Trace backpressure source, measure queue drain rate,
    simulate load shed impact."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[PipelineBackpressureRecord] = []
        self._analyses: dict[str, PipelineBackpressureAnalysis] = {}
        logger.info("pipeline_backpressure_analyzer_engine.init", max_records=max_records)

    def add_record(
        self,
        pipeline_id: str = "",
        pipeline_stage: PipelineStage = PipelineStage.RECEIVER,
        backpressure_level: BackpressureLevel = BackpressureLevel.NONE,
        propagation_direction: PropagationDirection = PropagationDirection.ISOLATED,
        queue_depth: int = 0,
        queue_capacity: int = 1,
        drain_rate_per_sec: float = 0.0,
        fill_rate_per_sec: float = 0.0,
        description: str = "",
    ) -> PipelineBackpressureRecord:
        record = PipelineBackpressureRecord(
            pipeline_id=pipeline_id,
            pipeline_stage=pipeline_stage,
            backpressure_level=backpressure_level,
            propagation_direction=propagation_direction,
            queue_depth=queue_depth,
            queue_capacity=queue_capacity,
            drain_rate_per_sec=drain_rate_per_sec,
            fill_rate_per_sec=fill_rate_per_sec,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "pipeline_backpressure.record_added",
            record_id=record.id,
            pipeline_id=pipeline_id,
        )
        return record

    def process(self, key: str) -> PipelineBackpressureAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        queue_fill_pct = round(
            (rec.queue_depth / rec.queue_capacity * 100.0) if rec.queue_capacity > 0 else 0.0,
            2,
        )
        drain_deficit = round(rec.fill_rate_per_sec - rec.drain_rate_per_sec, 4)
        source_stage = rec.pipeline_stage.value if queue_fill_pct > 80.0 else "none"
        analysis = PipelineBackpressureAnalysis(
            pipeline_id=rec.pipeline_id,
            pipeline_stage=rec.pipeline_stage,
            backpressure_level=rec.backpressure_level,
            queue_fill_pct=queue_fill_pct,
            source_stage=source_stage,
            drain_deficit=drain_deficit,
            description=(f"Pipeline {rec.pipeline_id} queue {queue_fill_pct:.1f}% full"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> PipelineBackpressureReport:
        by_stage: dict[str, int] = {}
        by_level: dict[str, int] = {}
        by_direction: dict[str, int] = {}
        fill_vals: list[float] = []
        critical: list[str] = []
        for r in self._records:
            ks = r.pipeline_stage.value
            by_stage[ks] = by_stage.get(ks, 0) + 1
            kl = r.backpressure_level.value
            by_level[kl] = by_level.get(kl, 0) + 1
            kd = r.propagation_direction.value
            by_direction[kd] = by_direction.get(kd, 0) + 1
            fill = (r.queue_depth / r.queue_capacity * 100.0) if r.queue_capacity > 0 else 0.0
            fill_vals.append(fill)
            if r.backpressure_level == BackpressureLevel.CRITICAL and r.pipeline_id not in critical:
                critical.append(r.pipeline_id)
        avg_fill = round(sum(fill_vals) / len(fill_vals), 2) if fill_vals else 0.0
        recs: list[str] = []
        if critical:
            recs.append(f"{len(critical)} pipelines with critical backpressure")
        severe = by_level.get("severe", 0)
        if severe > 0:
            recs.append(f"{severe} records with severe backpressure — load shed recommended")
        if not recs:
            recs.append("Pipeline backpressure is within acceptable thresholds")
        return PipelineBackpressureReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_queue_fill_pct=avg_fill,
            by_pipeline_stage=by_stage,
            by_backpressure_level=by_level,
            by_propagation_direction=by_direction,
            critical_pipelines=critical[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        level_dist: dict[str, int] = {}
        for r in self._records:
            k = r.backpressure_level.value
            level_dist[k] = level_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "backpressure_level_distribution": level_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("pipeline_backpressure_analyzer_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def trace_backpressure_source(self) -> list[dict[str, Any]]:
        """Identify the pipeline stage originating backpressure."""
        stage_data: dict[str, list[PipelineBackpressureRecord]] = {}
        for r in self._records:
            stage_data.setdefault(r.pipeline_stage.value, []).append(r)
        results: list[dict[str, Any]] = []
        for stage, recs in stage_data.items():
            critical_count = sum(
                1 for r in recs if r.backpressure_level == BackpressureLevel.CRITICAL
            )
            avg_fill = sum(
                (r.queue_depth / r.queue_capacity * 100.0) if r.queue_capacity > 0 else 0.0
                for r in recs
            ) / len(recs)
            avg_deficit = sum(r.fill_rate_per_sec - r.drain_rate_per_sec for r in recs) / len(recs)
            results.append(
                {
                    "stage": stage,
                    "critical_count": critical_count,
                    "avg_queue_fill_pct": round(avg_fill, 2),
                    "avg_drain_deficit": round(avg_deficit, 4),
                    "samples": len(recs),
                    "is_source": avg_fill > 75.0 and avg_deficit > 0,
                }
            )
        results.sort(key=lambda x: x["avg_queue_fill_pct"], reverse=True)
        return results

    def measure_queue_drain_rate(self) -> list[dict[str, Any]]:
        """Measure queue drain vs fill rate per pipeline."""
        pipeline_data: dict[str, list[PipelineBackpressureRecord]] = {}
        for r in self._records:
            pipeline_data.setdefault(r.pipeline_id, []).append(r)
        results: list[dict[str, Any]] = []
        for pid, recs in pipeline_data.items():
            avg_drain = sum(r.drain_rate_per_sec for r in recs) / len(recs)
            avg_fill = sum(r.fill_rate_per_sec for r in recs) / len(recs)
            deficit = avg_fill - avg_drain
            results.append(
                {
                    "pipeline_id": pid,
                    "avg_drain_rate": round(avg_drain, 4),
                    "avg_fill_rate": round(avg_fill, 4),
                    "deficit": round(deficit, 4),
                    "draining": deficit < 0,
                    "samples": len(recs),
                }
            )
        results.sort(key=lambda x: x["deficit"], reverse=True)
        return results

    def simulate_load_shed_impact(self) -> list[dict[str, Any]]:
        """Simulate impact of shedding 25%, 50%, 75% of incoming load."""
        pipeline_data: dict[str, list[PipelineBackpressureRecord]] = {}
        for r in self._records:
            pipeline_data.setdefault(r.pipeline_id, []).append(r)
        results: list[dict[str, Any]] = []
        for pid, recs in pipeline_data.items():
            avg_fill_rate = sum(r.fill_rate_per_sec for r in recs) / len(recs)
            avg_drain_rate = sum(r.drain_rate_per_sec for r in recs) / len(recs)
            scenarios: dict[str, Any] = {}
            for shed_pct in (25, 50, 75):
                shed_label = f"shed_{shed_pct}_pct"
                reduced_fill = avg_fill_rate * (1.0 - shed_pct / 100.0)
                net_deficit = reduced_fill - avg_drain_rate
                scenarios[shed_label] = {
                    "reduced_fill_rate": round(reduced_fill, 4),
                    "net_deficit": round(net_deficit, 4),
                    "relieved": net_deficit <= 0,
                }
            results.append(
                {
                    "pipeline_id": pid,
                    "avg_fill_rate": round(avg_fill_rate, 4),
                    "avg_drain_rate": round(avg_drain_rate, 4),
                    "scenarios": scenarios,
                }
            )
        results.sort(key=lambda x: x["avg_fill_rate"], reverse=True)
        return results
