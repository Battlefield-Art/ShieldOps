"""Runbook Step Reliability Engine — track individual runbook step reliability."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class StepType(StrEnum):
    COMMAND = "command"
    API_CALL = "api_call"
    SCRIPT = "script"
    APPROVAL_GATE = "approval_gate"
    VERIFICATION = "verification"
    ROLLBACK = "rollback"


class StepOutcome(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    RETRIED = "retried"


class FailureCategory(StrEnum):
    PERMISSION = "permission"
    TIMEOUT = "timeout"
    DEPENDENCY = "dependency"
    VALIDATION = "validation"
    INFRASTRUCTURE = "infrastructure"


class StepRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    step_id: str = ""
    step_type: StepType = StepType.COMMAND
    step_outcome: StepOutcome = StepOutcome.SUCCESS
    failure_category: FailureCategory = FailureCategory.PERMISSION
    runbook_name: str = ""
    step_name: str = ""
    duration_ms: float = 0.0
    retry_count: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class StepAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    step_id: str = ""
    step_type: StepType = StepType.COMMAND
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class StepReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    flaky_count: int = 0
    avg_duration_ms: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    by_failure: dict[str, int] = Field(default_factory=dict)
    top_flaky: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


class RunbookStepReliabilityEngine:
    """Track individual runbook step reliability."""

    def __init__(self, max_records: int = 200000, reliability_threshold: float = 95.0) -> None:
        self._max_records = max_records
        self._reliability_threshold = reliability_threshold
        self._records: list[StepRecord] = []
        self._analyses: list[StepAnalysis] = []
        logger.info("runbook_step_reliability_engine.initialized", max_records=max_records)

    def add_record(
        self,
        step_id: str,
        step_type: StepType = StepType.COMMAND,
        step_outcome: StepOutcome = StepOutcome.SUCCESS,
        failure_category: FailureCategory = FailureCategory.PERMISSION,
        runbook_name: str = "",
        step_name: str = "",
        duration_ms: float = 0.0,
        retry_count: int = 0,
        service: str = "",
        team: str = "",
    ) -> StepRecord:
        record = StepRecord(
            step_id=step_id,
            step_type=step_type,
            step_outcome=step_outcome,
            failure_category=failure_category,
            runbook_name=runbook_name,
            step_name=step_name,
            duration_ms=duration_ms,
            retry_count=retry_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        return record

    def get_record(self, record_id: str) -> StepRecord | None:
        return next((r for r in self._records if r.id == record_id), None)

    def list_records(
        self,
        step_type: StepType | None = None,
        step_outcome: StepOutcome | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[StepRecord]:
        results = list(self._records)
        if step_type:
            results = [r for r in results if r.step_type == step_type]
        if step_outcome:
            results = [r for r in results if r.step_outcome == step_outcome]
        if team:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        step_id: str,
        step_type: StepType = StepType.COMMAND,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> StepAnalysis:
        analysis = StepAnalysis(
            step_id=step_id,
            step_type=step_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    def analyze_step_reliability(self) -> dict[str, Any]:
        step_data: dict[str, list[bool]] = {}
        for r in self._records:
            step_data.setdefault(r.step_name, []).append(r.step_outcome == StepOutcome.SUCCESS)
        return {
            name: {
                "total": len(results),
                "success_rate": round(sum(results) / len(results) * 100, 2),
            }
            for name, results in step_data.items()
        }

    def identify_flaky_steps(self) -> list[dict[str, Any]]:
        step_stats = self.analyze_step_reliability()
        return sorted(
            [
                {"step": name, **stats}
                for name, stats in step_stats.items()
                if stats["success_rate"] < self._reliability_threshold
            ],
            key=lambda x: x["success_rate"],
        )

    def detect_reliability_trends(self) -> dict[str, Any]:
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [c.analysis_score for c in self._analyses]
        mid = len(vals) // 2
        avg_first = sum(vals[:mid]) / len(vals[:mid])
        avg_second = sum(vals[mid:]) / len(vals[mid:])
        delta = round(avg_second - avg_first, 2)
        trend = "stable" if abs(delta) < 5.0 else ("improving" if delta > 0 else "degrading")
        return {"trend": trend, "delta": delta}

    def generate_report(self) -> StepReport:
        by_type: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        by_failure: dict[str, int] = {}
        for r in self._records:
            by_type[r.step_type.value] = by_type.get(r.step_type.value, 0) + 1
            by_outcome[r.step_outcome.value] = by_outcome.get(r.step_outcome.value, 0) + 1
            if r.step_outcome == StepOutcome.FAILED:
                fc = r.failure_category.value
                by_failure[fc] = by_failure.get(fc, 0) + 1
        flaky = self.identify_flaky_steps()
        durations = [r.duration_ms for r in self._records if r.duration_ms > 0]
        avg_dur = round(sum(durations) / len(durations), 2) if durations else 0.0
        recs = []
        if flaky:
            recs.append(
                f"{len(flaky)} step(s) below reliability threshold ({self._reliability_threshold}%)"
            )
        if not recs:
            recs.append("All runbook steps are reliable")
        return StepReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            flaky_count=len(flaky),
            avg_duration_ms=avg_dur,
            by_type=by_type,
            by_outcome=by_outcome,
            by_failure=by_failure,
            top_flaky=[f["step"] for f in flaky[:5]],
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "reliability_threshold": self._reliability_threshold,
        }
