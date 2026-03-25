"""Runbook Execution Tracker Engine — track runbook execution outcomes and reliability."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class ExecutionOutcome(StrEnum):
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    TIMED_OUT = "timed_out"


class TriggerType(StrEnum):
    MANUAL = "manual"
    AUTOMATED = "automated"
    INCIDENT = "incident"
    SCHEDULED = "scheduled"
    ESCALATION = "escalation"


class ApprovalStatus(StrEnum):
    AUTO_APPROVED = "auto_approved"
    MANUALLY_APPROVED = "manually_approved"
    DENIED = "denied"
    PENDING = "pending"
    BYPASSED = "bypassed"


class ExecutionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    execution_id: str = ""
    execution_outcome: ExecutionOutcome = ExecutionOutcome.SUCCESS
    trigger_type: TriggerType = TriggerType.MANUAL
    approval_status: ApprovalStatus = ApprovalStatus.AUTO_APPROVED
    runbook_name: str = ""
    duration_min: float = 0.0
    steps_completed: int = 0
    rollback_triggered: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ExecutionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    execution_id: str = ""
    execution_outcome: ExecutionOutcome = ExecutionOutcome.SUCCESS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ExecutionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    failure_count: int = 0
    avg_duration_min: float = 0.0
    by_outcome: dict[str, int] = Field(default_factory=dict)
    by_trigger: dict[str, int] = Field(default_factory=dict)
    by_approval: dict[str, int] = Field(default_factory=dict)
    top_failures: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


class RunbookExecutionTrackerEngine:
    """Track runbook execution outcomes and reliability."""

    def __init__(self, max_records: int = 200000, success_threshold: float = 90.0) -> None:
        self._max_records = max_records
        self._success_threshold = success_threshold
        self._records: list[ExecutionRecord] = []
        self._analyses: list[ExecutionAnalysis] = []
        logger.info("runbook_execution_tracker_engine.initialized", max_records=max_records)

    def add_record(
        self,
        execution_id: str,
        execution_outcome: ExecutionOutcome = ExecutionOutcome.SUCCESS,
        trigger_type: TriggerType = TriggerType.MANUAL,
        approval_status: ApprovalStatus = ApprovalStatus.AUTO_APPROVED,
        runbook_name: str = "",
        duration_min: float = 0.0,
        steps_completed: int = 0,
        rollback_triggered: bool = False,
        service: str = "",
        team: str = "",
    ) -> ExecutionRecord:
        record = ExecutionRecord(
            execution_id=execution_id,
            execution_outcome=execution_outcome,
            trigger_type=trigger_type,
            approval_status=approval_status,
            runbook_name=runbook_name,
            duration_min=duration_min,
            steps_completed=steps_completed,
            rollback_triggered=rollback_triggered,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        return record

    def get_record(self, record_id: str) -> ExecutionRecord | None:
        return next((r for r in self._records if r.id == record_id), None)

    def list_records(
        self,
        execution_outcome: ExecutionOutcome | None = None,
        trigger_type: TriggerType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ExecutionRecord]:
        results = list(self._records)
        if execution_outcome:
            results = [r for r in results if r.execution_outcome == execution_outcome]
        if trigger_type:
            results = [r for r in results if r.trigger_type == trigger_type]
        if team:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        execution_id: str,
        execution_outcome: ExecutionOutcome = ExecutionOutcome.SUCCESS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ExecutionAnalysis:
        analysis = ExecutionAnalysis(
            execution_id=execution_id,
            execution_outcome=execution_outcome,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    def analyze_execution_success_rate(self) -> dict[str, Any]:
        if not self._records:
            return {"success_rate": 0.0, "total": 0}
        success = sum(1 for r in self._records if r.execution_outcome == ExecutionOutcome.SUCCESS)
        total = len(self._records)
        return {"success_rate": round(success / total * 100, 2), "total": total}

    def identify_failing_runbooks(self) -> list[dict[str, Any]]:
        failures: dict[str, int] = {}
        for r in self._records:
            if r.execution_outcome in {ExecutionOutcome.FAILED, ExecutionOutcome.TIMED_OUT}:
                failures[r.runbook_name] = failures.get(r.runbook_name, 0) + 1
        return sorted(
            [{"runbook": k, "failures": v} for k, v in failures.items()],
            key=lambda x: x["failures"],
            reverse=True,
        )

    def detect_automation_trends(self) -> dict[str, Any]:
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [c.analysis_score for c in self._analyses]
        mid = len(vals) // 2
        avg_first = sum(vals[:mid]) / len(vals[:mid])
        avg_second = sum(vals[mid:]) / len(vals[mid:])
        delta = round(avg_second - avg_first, 2)
        trend = "stable" if abs(delta) < 5.0 else ("improving" if delta > 0 else "degrading")
        return {"trend": trend, "delta": delta}

    def generate_report(self) -> ExecutionReport:
        by_outcome: dict[str, int] = {}
        by_trigger: dict[str, int] = {}
        by_approval: dict[str, int] = {}
        for r in self._records:
            by_outcome[r.execution_outcome.value] = by_outcome.get(r.execution_outcome.value, 0) + 1
            by_trigger[r.trigger_type.value] = by_trigger.get(r.trigger_type.value, 0) + 1
            by_approval[r.approval_status.value] = by_approval.get(r.approval_status.value, 0) + 1
        failures = self.identify_failing_runbooks()
        durations = [r.duration_min for r in self._records if r.duration_min > 0]
        avg_dur = round(sum(durations) / len(durations), 2) if durations else 0.0
        recs = []
        fail_outcomes = {ExecutionOutcome.FAILED, ExecutionOutcome.TIMED_OUT}
        fail_count = sum(1 for r in self._records if r.execution_outcome in fail_outcomes)
        if fail_count > 0:
            recs.append(f"{fail_count} execution(s) failed or timed out")
        if not recs:
            recs.append("Runbook execution reliability is healthy")
        return ExecutionReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            failure_count=fail_count,
            avg_duration_min=avg_dur,
            by_outcome=by_outcome,
            by_trigger=by_trigger,
            by_approval=by_approval,
            top_failures=[f["runbook"] for f in failures[:5]],
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
            "success_threshold": self._success_threshold,
        }
