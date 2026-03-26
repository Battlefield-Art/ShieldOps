"""Threat Playbook Engine —
manage threat response playbooks,
track execution outcomes, optimize playbook selection."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PlaybookType(StrEnum):
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    INVESTIGATION = "investigation"
    NOTIFICATION = "notification"


class ExecutionMode(StrEnum):
    AUTOMATIC = "automatic"
    SEMI_AUTOMATIC = "semi_automatic"
    MANUAL = "manual"
    SIMULATION = "simulation"
    DISABLED = "disabled"


class PlaybookOutcome(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    ESCALATED = "escalated"
    ABORTED = "aborted"


# --- Models ---


class ThreatPlaybookRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    playbook_name: str = ""
    threat_type: str = ""
    playbook_type: PlaybookType = PlaybookType.CONTAINMENT
    execution_mode: ExecutionMode = ExecutionMode.AUTOMATIC
    playbook_outcome: PlaybookOutcome = PlaybookOutcome.SUCCESS
    execution_time_seconds: float = 0.0
    steps_total: int = 0
    steps_completed: int = 0
    affected_assets: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ThreatPlaybookAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    playbook_name: str = ""
    playbook_type: PlaybookType = PlaybookType.CONTAINMENT
    success_rate: float = 0.0
    avg_execution_time: float = 0.0
    completion_rate: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ThreatPlaybookReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    overall_success_rate: float = 0.0
    by_playbook_type: dict[str, int] = Field(default_factory=dict)
    by_execution_mode: dict[str, int] = Field(default_factory=dict)
    by_playbook_outcome: dict[str, int] = Field(default_factory=dict)
    failing_playbooks: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ThreatPlaybookEngine:
    """Manage threat response playbooks,
    track execution outcomes, optimize playbook selection."""

    def __init__(self, max_records: int = 200000, success_threshold: float = 90.0) -> None:
        self._max_records = max_records
        self._success_threshold = success_threshold
        self._records: list[ThreatPlaybookRecord] = []
        self._analyses: dict[str, ThreatPlaybookAnalysis] = {}
        logger.info(
            "threat_playbook_engine.init",
            max_records=max_records,
            success_threshold=success_threshold,
        )

    def add_record(
        self,
        playbook_name: str = "",
        threat_type: str = "",
        playbook_type: PlaybookType = PlaybookType.CONTAINMENT,
        execution_mode: ExecutionMode = ExecutionMode.AUTOMATIC,
        playbook_outcome: PlaybookOutcome = PlaybookOutcome.SUCCESS,
        execution_time_seconds: float = 0.0,
        steps_total: int = 0,
        steps_completed: int = 0,
        affected_assets: int = 0,
        description: str = "",
    ) -> ThreatPlaybookRecord:
        record = ThreatPlaybookRecord(
            playbook_name=playbook_name,
            threat_type=threat_type,
            playbook_type=playbook_type,
            execution_mode=execution_mode,
            playbook_outcome=playbook_outcome,
            execution_time_seconds=execution_time_seconds,
            steps_total=steps_total,
            steps_completed=steps_completed,
            affected_assets=affected_assets,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "threat_playbook.record_added",
            record_id=record.id,
            playbook_name=playbook_name,
        )
        return record

    def process(self, key: str) -> ThreatPlaybookAnalysis | dict[str, Any]:
        recs = [r for r in self._records if r.playbook_name == key or r.id == key]
        if not recs:
            return {"status": "not_found", "key": key}
        successes = sum(1 for r in recs if r.playbook_outcome == PlaybookOutcome.SUCCESS)
        success_rate = round(successes / len(recs) * 100, 2)
        avg_time = round(sum(r.execution_time_seconds for r in recs) / len(recs), 2)
        total_steps = sum(r.steps_total for r in recs)
        completed_steps = sum(r.steps_completed for r in recs)
        completion = round(completed_steps / total_steps * 100, 2) if total_steps > 0 else 0.0
        analysis = ThreatPlaybookAnalysis(
            playbook_name=recs[0].playbook_name,
            playbook_type=recs[0].playbook_type,
            success_rate=success_rate,
            avg_execution_time=avg_time,
            completion_rate=completion,
            description=(
                f"{recs[0].playbook_name} success={success_rate}% "
                f"avg_time={avg_time}s completion={completion}%"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ThreatPlaybookReport:
        by_type: dict[str, int] = {}
        by_mode: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        for r in self._records:
            pt = r.playbook_type.value
            by_type[pt] = by_type.get(pt, 0) + 1
            em = r.execution_mode.value
            by_mode[em] = by_mode.get(em, 0) + 1
            po = r.playbook_outcome.value
            by_outcome[po] = by_outcome.get(po, 0) + 1
        successes = by_outcome.get("success", 0)
        total = len(self._records)
        overall = round(successes / total * 100, 2) if total else 0.0
        failing = list(
            {
                r.playbook_name
                for r in self._records
                if r.playbook_outcome in (PlaybookOutcome.FAILED, PlaybookOutcome.ABORTED)
            }
        )[:10]
        recs: list[str] = []
        if overall < self._success_threshold:
            recs.append(f"Overall success rate {overall}% below {self._success_threshold}% target")
        if failing:
            recs.append(f"{len(failing)} playbooks with failures — review and update")
        if not recs:
            recs.append("Threat playbook execution within acceptable parameters")
        return ThreatPlaybookReport(
            total_records=total,
            total_analyses=len(self._analyses),
            overall_success_rate=overall,
            by_playbook_type=by_type,
            by_execution_mode=by_mode,
            by_playbook_outcome=by_outcome,
            failing_playbooks=failing,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        outcome_dist: dict[str, int] = {}
        for r in self._records:
            k = r.playbook_outcome.value
            outcome_dist[k] = outcome_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "outcome_distribution": outcome_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("threat_playbook_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def find_slow_playbooks(self) -> list[dict[str, Any]]:
        """Find playbooks with above-average execution times."""
        if not self._records:
            return []
        avg_time = sum(r.execution_time_seconds for r in self._records) / len(self._records)
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.execution_time_seconds > avg_time * 1.5:
                results.append(
                    {
                        "playbook_name": r.playbook_name,
                        "playbook_type": r.playbook_type.value,
                        "execution_time_seconds": r.execution_time_seconds,
                        "avg_time_seconds": round(avg_time, 2),
                        "slowdown_factor": round(r.execution_time_seconds / avg_time, 2)
                        if avg_time > 0
                        else 0.0,
                    }
                )
        results.sort(key=lambda x: x["execution_time_seconds"], reverse=True)
        return results

    def analyze_automation_coverage(self) -> list[dict[str, Any]]:
        """Analyze automation level across playbook types."""
        type_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            pt = r.playbook_type.value
            type_data.setdefault(pt, {"total": 0, "auto": 0, "manual": 0})
            type_data[pt]["total"] += 1
            if r.execution_mode == ExecutionMode.AUTOMATIC:
                type_data[pt]["auto"] += 1
            if r.execution_mode == ExecutionMode.MANUAL:
                type_data[pt]["manual"] += 1
        results: list[dict[str, Any]] = []
        for ptype, data in type_data.items():
            auto_pct = round(data["auto"] / data["total"] * 100, 2) if data["total"] > 0 else 0.0
            results.append(
                {
                    "playbook_type": ptype,
                    "total_executions": data["total"],
                    "automatic": data["auto"],
                    "manual": data["manual"],
                    "automation_pct": auto_pct,
                }
            )
        results.sort(key=lambda x: x["automation_pct"])
        return results

    def rank_playbooks_by_effectiveness(self) -> list[dict[str, Any]]:
        """Rank playbooks by combined success and completion rate."""
        pb_data: dict[str, list[ThreatPlaybookRecord]] = {}
        for r in self._records:
            pb_data.setdefault(r.playbook_name, []).append(r)
        results: list[dict[str, Any]] = []
        for pb, recs in pb_data.items():
            successes = sum(1 for r in recs if r.playbook_outcome == PlaybookOutcome.SUCCESS)
            success_rate = successes / len(recs) * 100 if recs else 0.0
            total_steps = sum(r.steps_total for r in recs)
            completed = sum(r.steps_completed for r in recs)
            completion = completed / total_steps * 100 if total_steps > 0 else 0.0
            effectiveness = round((success_rate + completion) / 2, 2)
            results.append(
                {
                    "playbook_name": pb,
                    "execution_count": len(recs),
                    "success_rate": round(success_rate, 2),
                    "completion_rate": round(completion, 2),
                    "effectiveness_score": effectiveness,
                    "rank": 0,
                }
            )
        results.sort(key=lambda x: x["effectiveness_score"], reverse=True)
        for idx, entry in enumerate(results, 1):
            entry["rank"] = idx
        return results
