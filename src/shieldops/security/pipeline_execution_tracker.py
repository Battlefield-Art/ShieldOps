"""PipelineExecutionTracker — track security pipeline cycles."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PipelineCycle(StrEnum):
    FULL = "full"
    INCREMENTAL = "incremental"
    TARGETED = "targeted"


class ExecutionPhase(StrEnum):
    INTAKE = "intake"
    ANALYSIS = "analysis"
    CORRELATION = "correlation"
    TRIAGE = "triage"
    REMEDIATION = "remediation"


class CycleOutcome(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


# --- Models ---


class PipelineExecutionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    pipeline_cycle: PipelineCycle = PipelineCycle.FULL
    execution_phase: ExecutionPhase = ExecutionPhase.INTAKE
    cycle_outcome: CycleOutcome = CycleOutcome.SUCCESS
    score: float = 0.0
    duration_ms: float = 0.0
    findings_processed: int = 0
    entity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class PipelineExecutionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    pipeline_cycle: PipelineCycle = PipelineCycle.FULL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PipelineExecutionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_pipeline_cycle: dict[str, int] = Field(default_factory=dict)
    by_execution_phase: dict[str, int] = Field(default_factory=dict)
    by_cycle_outcome: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class PipelineExecutionTracker:
    """Track security pipeline execution cycles."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[PipelineExecutionRecord] = []
        self._analyses: list[PipelineExecutionAnalysis] = []
        logger.info(
            "pipeline_execution_tracker.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ---

    def add_record(
        self,
        name: str,
        pipeline_cycle: PipelineCycle = (PipelineCycle.FULL),
        execution_phase: ExecutionPhase = (ExecutionPhase.INTAKE),
        cycle_outcome: CycleOutcome = (CycleOutcome.SUCCESS),
        score: float = 0.0,
        duration_ms: float = 0.0,
        findings_processed: int = 0,
        entity: str = "",
        service: str = "",
        team: str = "",
    ) -> PipelineExecutionRecord:
        record = PipelineExecutionRecord(
            name=name,
            pipeline_cycle=pipeline_cycle,
            execution_phase=execution_phase,
            cycle_outcome=cycle_outcome,
            score=score,
            duration_ms=duration_ms,
            findings_processed=findings_processed,
            entity=entity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "pipeline_execution_tracker.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> PipelineExecutionRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        pipeline_cycle: PipelineCycle | None = None,
        cycle_outcome: CycleOutcome | None = None,
        limit: int = 50,
    ) -> list[PipelineExecutionRecord]:
        results = list(self._records)
        if pipeline_cycle is not None:
            results = [r for r in results if r.pipeline_cycle == pipeline_cycle]
        if cycle_outcome is not None:
            results = [r for r in results if r.cycle_outcome == cycle_outcome]
        return results[-limit:]

    # -- domain methods ---

    def track_cycle(self) -> list[dict[str, Any]]:
        """Track pipeline cycle execution patterns."""
        cycle_data: dict[str, list[PipelineExecutionRecord]] = {}
        for r in self._records:
            cycle_data.setdefault(r.pipeline_cycle.value, []).append(r)
        results: list[dict[str, Any]] = []
        for cycle, records in cycle_data.items():
            durations = [r.duration_ms for r in records]
            avg_dur = sum(durations) / len(durations) if durations else 0.0
            results.append(
                {
                    "cycle": cycle,
                    "count": len(records),
                    "avg_duration_ms": round(avg_dur, 2),
                    "total_findings": sum(r.findings_processed for r in records),
                }
            )
        return sorted(
            results,
            key=lambda x: x["count"],
            reverse=True,
        )

    def measure_throughput(self) -> dict[str, Any]:
        """Measure pipeline throughput metrics."""
        if not self._records:
            return {
                "total_cycles": 0,
                "throughput_per_hour": 0.0,
            }
        total = len(self._records)
        findings = sum(r.findings_processed for r in self._records)
        durations = [r.duration_ms for r in self._records]
        total_ms = sum(durations)
        return {
            "total_cycles": total,
            "total_findings": findings,
            "avg_duration_ms": round(total_ms / total, 2),
            "throughput_per_hour": round(
                findings / max(total_ms / 3600000, 1),
                2,
            ),
        }

    def detect_bottlenecks(
        self,
    ) -> list[dict[str, Any]]:
        """Detect slow phases in the pipeline."""
        phase_data: dict[str, list[float]] = {}
        for r in self._records:
            phase_data.setdefault(r.execution_phase.value, []).append(r.duration_ms)
        bottlenecks: list[dict[str, Any]] = []
        for phase, durations in phase_data.items():
            avg = sum(durations) / len(durations)
            if avg > self._threshold:
                bottlenecks.append(
                    {
                        "phase": phase,
                        "avg_duration_ms": round(avg, 2),
                        "sample_count": len(durations),
                        "severity": ("high" if avg > self._threshold * 2 else "moderate"),
                    }
                )
        return sorted(
            bottlenecks,
            key=lambda x: x["avg_duration_ms"],
            reverse=True,
        )

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
        }

    def generate_report(
        self,
    ) -> PipelineExecutionReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.pipeline_cycle.value] = by_e1.get(r.pipeline_cycle.value, 0) + 1
            by_e2[r.execution_phase.value] = by_e2.get(r.execution_phase.value, 0) + 1
            by_e3[r.cycle_outcome.value] = by_e3.get(r.cycle_outcome.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gaps = [r.name for r in self._records if r.score < self._threshold][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Pipeline execution is healthy")
        return PipelineExecutionReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_pipeline_cycle=by_e1,
            by_execution_phase=by_e2,
            by_cycle_outcome=by_e3,
            top_gaps=gaps,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.pipeline_cycle.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "cycle_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("pipeline_execution_tracker.cleared")
        return {"status": "cleared"}
