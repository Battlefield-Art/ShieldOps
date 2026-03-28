"""IR Playbook Tracker — track IR playbook execution and adaptation."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PlaybookPhase(StrEnum):
    PREPARATION = "preparation"
    IDENTIFICATION = "identification"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"


class ExecutionOutcome(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    ADAPTED = "adapted"


class AdaptationType(StrEnum):
    STEP_REORDER = "step_reorder"
    STEP_SKIP = "step_skip"
    STEP_ADD = "step_add"
    THRESHOLD_CHANGE = "threshold_change"
    ESCALATION = "escalation"


# --- Models ---


class PlaybookRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    playbook_name: str = ""
    phase: PlaybookPhase = PlaybookPhase.PREPARATION
    outcome: ExecutionOutcome = ExecutionOutcome.SUCCESS
    adaptation: AdaptationType = AdaptationType.STEP_REORDER
    incident_id: str = ""
    execution_time_ms: float = 0.0
    steps_total: int = 0
    steps_completed: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class PlaybookAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    playbook_name: str = ""
    phase: PlaybookPhase = PlaybookPhase.PREPARATION
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PlaybookReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_execution_time_ms: float = 0.0
    success_rate: float = 0.0
    by_phase: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    by_adaptation: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class IRPlaybookTrackerEngine:
    """Track IR playbook execution and adaptation."""

    def __init__(
        self,
        max_records: int = 200000,
        time_threshold_ms: float = 30000.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = time_threshold_ms
        self._records: list[PlaybookRecord] = []
        self._analyses: list[PlaybookAnalysis] = []
        logger.info(
            "ir_playbook_tracker.initialized",
            max_records=max_records,
            time_threshold_ms=time_threshold_ms,
        )

    # -- record / get / list ---

    def add_record(
        self,
        playbook_name: str,
        phase: PlaybookPhase = PlaybookPhase.PREPARATION,
        outcome: ExecutionOutcome = (ExecutionOutcome.SUCCESS),
        adaptation: AdaptationType = (AdaptationType.STEP_REORDER),
        incident_id: str = "",
        execution_time_ms: float = 0.0,
        steps_total: int = 0,
        steps_completed: int = 0,
        service: str = "",
        team: str = "",
    ) -> PlaybookRecord:
        record = PlaybookRecord(
            playbook_name=playbook_name,
            phase=phase,
            outcome=outcome,
            adaptation=adaptation,
            incident_id=incident_id,
            execution_time_ms=execution_time_ms,
            steps_total=steps_total,
            steps_completed=steps_completed,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ir_playbook_tracker.record_added",
            record_id=record.id,
            playbook_name=playbook_name,
            phase=phase.value,
        )
        return record

    def get_record(self, record_id: str) -> PlaybookRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        phase: PlaybookPhase | None = None,
        outcome: ExecutionOutcome | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[PlaybookRecord]:
        results = list(self._records)
        if phase is not None:
            results = [r for r in results if r.phase == phase]
        if outcome is not None:
            results = [r for r in results if r.outcome == outcome]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        playbook_name: str,
        phase: PlaybookPhase = PlaybookPhase.PREPARATION,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> PlaybookAnalysis:
        analysis = PlaybookAnalysis(
            playbook_name=playbook_name,
            phase=phase,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "ir_playbook_tracker.analysis_added",
            playbook_name=playbook_name,
            phase=phase.value,
        )
        return analysis

    # -- domain operations ---

    def track_playbook(self) -> list[dict[str, Any]]:
        """Track playbook usage across phases."""
        phase_data: dict[str, list[PlaybookRecord]] = {}
        for r in self._records:
            phase_data.setdefault(r.phase.value, []).append(r)
        results: list[dict[str, Any]] = []
        for phase, records in phase_data.items():
            success = sum(1 for r in records if r.outcome == ExecutionOutcome.SUCCESS)
            rate = round(success / len(records) * 100, 2) if records else 0.0
            results.append(
                {
                    "phase": phase,
                    "total": len(records),
                    "success_count": success,
                    "success_rate": rate,
                }
            )
        return sorted(
            results,
            key=lambda x: x["success_rate"],
        )

    def measure_execution_time(
        self,
    ) -> list[dict[str, Any]]:
        """Measure execution time by playbook."""
        pb_data: dict[str, list[PlaybookRecord]] = {}
        for r in self._records:
            pb_data.setdefault(r.playbook_name, []).append(r)
        results: list[dict[str, Any]] = []
        for name, records in pb_data.items():
            times = [r.execution_time_ms for r in records]
            avg = round(sum(times) / len(times), 2) if times else 0.0
            slow = sum(1 for t in times if t > self._threshold)
            results.append(
                {
                    "playbook": name,
                    "count": len(records),
                    "avg_ms": avg,
                    "slow_count": slow,
                    "max_ms": max(times) if times else 0.0,
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_ms"],
            reverse=True,
        )

    def detect_adaptation_triggers(
        self,
    ) -> list[dict[str, Any]]:
        """Detect what triggers playbook adaptation."""
        adapt_data: dict[str, list[PlaybookRecord]] = {}
        for r in self._records:
            if r.outcome == ExecutionOutcome.ADAPTED:
                adapt_data.setdefault(r.adaptation.value, []).append(r)
        results: list[dict[str, Any]] = []
        for adapt_type, records in adapt_data.items():
            phases = [r.phase.value for r in records]
            phase_dist: dict[str, int] = {}
            for p in phases:
                phase_dist[p] = phase_dist.get(p, 0) + 1
            results.append(
                {
                    "adaptation_type": adapt_type,
                    "count": len(records),
                    "phase_distribution": phase_dist,
                }
            )
        return sorted(
            results,
            key=lambda x: x["count"],
            reverse=True,
        )

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.playbook_name == key or r.incident_id == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        times = [r.execution_time_ms for r in matched]
        avg = round(sum(times) / len(times), 2) if times else 0.0
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_execution_time_ms": avg,
        }

    def generate_report(self) -> PlaybookReport:
        by_phase: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        by_adaptation: dict[str, int] = {}
        for r in self._records:
            by_phase[r.phase.value] = by_phase.get(r.phase.value, 0) + 1
            by_outcome[r.outcome.value] = by_outcome.get(r.outcome.value, 0) + 1
            by_adaptation[r.adaptation.value] = by_adaptation.get(r.adaptation.value, 0) + 1
        times = [r.execution_time_ms for r in self._records]
        avg_time = round(sum(times) / len(times), 2) if times else 0.0
        successes = sum(1 for r in self._records if r.outcome == ExecutionOutcome.SUCCESS)
        rate = (
            round(
                successes / len(self._records) * 100,
                2,
            )
            if self._records
            else 0.0
        )
        recs: list[str] = []
        if self._records and rate < 80:
            recs.append(f"Success rate {rate}% below 80%")
        if self._records and avg_time > self._threshold:
            recs.append(f"Avg time {avg_time}ms exceeds threshold {self._threshold}ms")
        if not recs:
            recs.append("IR Playbook Tracker is healthy")
        return PlaybookReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_execution_time_ms=avg_time,
            success_rate=rate,
            by_phase=by_phase,
            by_outcome=by_outcome,
            by_adaptation=by_adaptation,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("ir_playbook_tracker.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        phase_dist: dict[str, int] = {}
        for r in self._records:
            k = r.phase.value
            phase_dist[k] = phase_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "time_threshold_ms": self._threshold,
            "phase_distribution": phase_dist,
            "unique_playbooks": len({r.playbook_name for r in self._records}),
            "unique_teams": len({r.team for r in self._records}),
        }
