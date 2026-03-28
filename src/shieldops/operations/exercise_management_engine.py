"""Exercise Management Engine — manage incident exercises and scoring."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ExercisePhase(StrEnum):
    PLANNING = "planning"
    BRIEFING = "briefing"
    EXECUTION = "execution"
    HOT_WASH = "hot_wash"
    AFTER_ACTION = "after_action"


class InjectType(StrEnum):
    SCENARIO_UPDATE = "scenario_update"
    COMPLICATION = "complication"
    RESOURCE_CHANGE = "resource_change"
    EXTERNAL_EVENT = "external_event"
    TIME_PRESSURE = "time_pressure"


class ScoreCategory(StrEnum):
    DETECTION = "detection"
    RESPONSE = "response"
    COMMUNICATION = "communication"
    DECISION_MAKING = "decision_making"
    RECOVERY = "recovery"


# --- Models ---


class ExerciseRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    exercise_name: str = ""
    phase: ExercisePhase = ExercisePhase.PLANNING
    inject_type: InjectType = InjectType.SCENARIO_UPDATE
    score_category: ScoreCategory = ScoreCategory.DETECTION
    score: float = 0.0
    team_name: str = ""
    participants: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ExerciseAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    exercise_name: str = ""
    phase: ExercisePhase = ExercisePhase.PLANNING
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ExerciseReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_score: float = 0.0
    by_phase: dict[str, int] = Field(default_factory=dict)
    by_inject: dict[str, int] = Field(default_factory=dict)
    by_score_category: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ExerciseManagementEngine:
    """Manage incident exercises and scoring."""

    def __init__(
        self,
        max_records: int = 200000,
        score_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = score_threshold
        self._records: list[ExerciseRecord] = []
        self._analyses: list[ExerciseAnalysis] = []
        logger.info(
            "exercise_management.initialized",
            max_records=max_records,
        )

    def record_item(
        self,
        exercise_name: str,
        phase: ExercisePhase = (ExercisePhase.PLANNING),
        inject_type: InjectType = (InjectType.SCENARIO_UPDATE),
        score_category: ScoreCategory = (ScoreCategory.DETECTION),
        score: float = 0.0,
        team_name: str = "",
        participants: int = 0,
        service: str = "",
        team: str = "",
    ) -> ExerciseRecord:
        record = ExerciseRecord(
            exercise_name=exercise_name,
            phase=phase,
            inject_type=inject_type,
            score_category=score_category,
            score=score,
            team_name=team_name,
            participants=participants,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "exercise_management.record_added",
            record_id=record.id,
            exercise_name=exercise_name,
        )
        return record

    def get_record(self, record_id: str) -> ExerciseRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        phase: ExercisePhase | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ExerciseRecord]:
        results = list(self._records)
        if phase is not None:
            results = [r for r in results if r.phase == phase]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    # -- domain operations ---

    def manage_exercise(
        self,
    ) -> list[dict[str, Any]]:
        """Summarize exercises by name."""
        ex_data: dict[str, list[ExerciseRecord]] = {}
        for r in self._records:
            ex_data.setdefault(r.exercise_name, []).append(r)
        results: list[dict[str, Any]] = []
        for name, records in ex_data.items():
            scores = [r.score for r in records]
            avg = round(sum(scores) / len(scores), 2) if scores else 0.0
            results.append(
                {
                    "exercise": name,
                    "records": len(records),
                    "avg_score": avg,
                    "participants": sum(r.participants for r in records),
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_score"],
        )

    def inject_scenario(
        self,
    ) -> list[dict[str, Any]]:
        """Analyze inject distribution."""
        inj_data: dict[str, list[ExerciseRecord]] = {}
        for r in self._records:
            inj_data.setdefault(r.inject_type.value, []).append(r)
        results: list[dict[str, Any]] = []
        for inj, records in inj_data.items():
            scores = [r.score for r in records]
            avg = round(sum(scores) / len(scores), 2) if scores else 0.0
            results.append(
                {
                    "inject_type": inj,
                    "count": len(records),
                    "avg_score": avg,
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_score"],
        )

    def score_performance(
        self,
    ) -> list[dict[str, Any]]:
        """Score performance by category."""
        cat_data: dict[str, list[ExerciseRecord]] = {}
        for r in self._records:
            cat_data.setdefault(r.score_category.value, []).append(r)
        results: list[dict[str, Any]] = []
        for cat, records in cat_data.items():
            scores = [r.score for r in records]
            avg = round(sum(scores) / len(scores), 2) if scores else 0.0
            below = sum(1 for s in scores if s < self._threshold)
            results.append(
                {
                    "category": cat,
                    "count": len(records),
                    "avg_score": avg,
                    "below_threshold": below,
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_score"],
        )

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.exercise_name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
        }

    def generate_report(self) -> ExerciseReport:
        by_phase: dict[str, int] = {}
        by_inj: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        for r in self._records:
            by_phase[r.phase.value] = by_phase.get(r.phase.value, 0) + 1
            by_inj[r.inject_type.value] = by_inj.get(r.inject_type.value, 0) + 1
            by_cat[r.score_category.value] = by_cat.get(r.score_category.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        recs: list[str] = []
        if avg < self._threshold:
            recs.append(f"Avg score {avg} below {self._threshold}")
        if not recs:
            recs.append("Exercise Management is healthy")
        return ExerciseReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_score=avg,
            by_phase=by_phase,
            by_inject=by_inj,
            by_score_category=by_cat,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("exercise_management.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        phase_dist: dict[str, int] = {}
        for r in self._records:
            k = r.phase.value
            phase_dist[k] = phase_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "score_threshold": self._threshold,
            "phase_distribution": phase_dist,
            "unique_exercises": len({r.exercise_name for r in self._records}),
        }
