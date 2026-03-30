"""Remediation Pipeline Tracker — track pipelines."""

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
    INTAKE = "intake"
    TRIAGE = "triage"
    PLANNING = "planning"
    EXECUTION = "execution"
    VERIFICATION = "verification"
    CLOSURE = "closure"


class BottleneckType(StrEnum):
    APPROVAL_DELAY = "approval_delay"
    RESOURCE_CONTENTION = "resource_contention"
    DEPENDENCY_WAIT = "dependency_wait"
    MANUAL_STEP = "manual_step"
    TOOL_FAILURE = "tool_failure"


class SLAStatus(StrEnum):
    WITHIN_SLA = "within_sla"
    AT_RISK = "at_risk"
    BREACHED = "breached"
    WAIVED = "waived"
    NOT_APPLICABLE = "not_applicable"


# --- Models ---


class PipelineRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    remediation_id: str = ""
    stage: PipelineStage = PipelineStage.INTAKE
    bottleneck: str = ""
    sla_status: SLAStatus = SLAStatus.WITHIN_SLA
    duration_sec: float = 0.0
    blocked: bool = False
    created_at: float = Field(default_factory=time.time)


class PipelineAnalysis(BaseModel):
    remediation_id: str = ""
    stages_completed: int = 0
    total_duration_sec: float = 0.0
    bottlenecks_hit: int = 0
    sla_status: str = ""
    analyzed_at: float = Field(default_factory=time.time)


class PipelineReport(BaseModel):
    total_pipelines: int = 0
    avg_duration_sec: float = 0.0
    sla_breach_count: int = 0
    by_stage: dict[str, int] = Field(default_factory=dict)
    by_bottleneck: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class RemediationPipelineTracker:
    """Track remediation pipeline progress."""

    def __init__(self, max_records: int = 10000) -> None:
        self._max = max_records
        self._records: list[PipelineRecord] = []
        logger.info(
            "remediation_pipeline_tracker.init",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> PipelineRecord:
        rec = PipelineRecord(**kwargs)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "remediation_pipeline.recorded",
            record_id=rec.id,
        )
        return rec

    def process(self, remediation_id: str) -> PipelineAnalysis:
        recs = [r for r in self._records if r.remediation_id == remediation_id]
        if not recs:
            return PipelineAnalysis(remediation_id=remediation_id)
        total_dur = sum(r.duration_sec for r in recs)
        bottlenecks = sum(1 for r in recs if r.bottleneck)
        breached = any(r.sla_status == SLAStatus.BREACHED for r in recs)
        sla = "breached" if breached else "on_track"
        return PipelineAnalysis(
            remediation_id=remediation_id,
            stages_completed=len(recs),
            total_duration_sec=round(total_dur, 2),
            bottlenecks_hit=bottlenecks,
            sla_status=sla,
        )

    def generate_report(self) -> PipelineReport:
        by_stage: dict[str, int] = {}
        by_bn: dict[str, int] = {}
        for r in self._records:
            s = r.stage.value
            by_stage[s] = by_stage.get(s, 0) + 1
            if r.bottleneck:
                by_bn[r.bottleneck] = by_bn.get(r.bottleneck, 0) + 1
        total = len(self._records)
        durations = [r.duration_sec for r in self._records if r.duration_sec > 0]
        avg_dur = round(sum(durations) / len(durations), 2) if durations else 0.0
        breaches = sum(1 for r in self._records if r.sla_status == SLAStatus.BREACHED)
        recs: list[str] = []
        if breaches > 0:
            recs.append(f"{breaches} SLA breach(es)")
        if by_bn:
            top = max(by_bn, key=lambda k: by_bn.get(k, 0))
            recs.append(f"Top bottleneck: {top}")
        if not recs:
            recs.append("Pipeline flowing smoothly")
        return PipelineReport(
            total_pipelines=total,
            avg_duration_sec=avg_dur,
            sla_breach_count=breaches,
            by_stage=by_stage,
            by_bottleneck=by_bn,
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
        logger.info("remediation_pipeline_tracker.cleared")

    # -- domain methods --

    def track_pipeline(
        self,
        remediation_id: str,
        stage: PipelineStage,
        duration_sec: float = 0.0,
        bottleneck: str = "",
        sla_status: SLAStatus = (SLAStatus.WITHIN_SLA),
    ) -> PipelineRecord:
        """Record a pipeline stage event."""
        return self.add_record(
            remediation_id=remediation_id,
            stage=stage,
            duration_sec=duration_sec,
            bottleneck=bottleneck,
            sla_status=sla_status,
        )

    def identify_bottlenecks(
        self,
    ) -> list[dict[str, Any]]:
        """Find recurring bottlenecks."""
        bns: dict[str, int] = {}
        for r in self._records:
            if r.bottleneck:
                bns[r.bottleneck] = bns.get(r.bottleneck, 0) + 1
        return [
            {"bottleneck": b, "count": c}
            for b, c in sorted(
                bns.items(),
                key=lambda x: x[1],
                reverse=True,
            )
        ]

    def measure_end_to_end_time(self, remediation_id: str) -> dict[str, Any]:
        """Measure total pipeline duration."""
        recs = [r for r in self._records if r.remediation_id == remediation_id]
        if not recs:
            return {
                "remediation_id": remediation_id,
                "found": False,
            }
        total = sum(r.duration_sec for r in recs)
        return {
            "remediation_id": remediation_id,
            "found": True,
            "stages": len(recs),
            "total_duration_sec": round(total, 2),
            "blocked_stages": sum(1 for r in recs if r.blocked),
        }
