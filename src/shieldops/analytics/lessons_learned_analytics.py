"""Lessons Learned Analytics — track lessons and recurrence."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class LessonCategory(StrEnum):
    PROCESS = "process"
    TOOLING = "tooling"
    COMMUNICATION = "communication"
    DETECTION = "detection"
    RESPONSE = "response"


class RecurrenceRate(StrEnum):
    NONE = "none"
    RARE = "rare"
    OCCASIONAL = "occasional"
    FREQUENT = "frequent"
    CHRONIC = "chronic"


class ImplementationStatus(StrEnum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    DEFERRED = "deferred"


# --- Models ---


class LessonRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    category: LessonCategory = LessonCategory.PROCESS
    recurrence: RecurrenceRate = RecurrenceRate.NONE
    status: ImplementationStatus = ImplementationStatus.PROPOSED
    lesson_text: str = ""
    action_item: str = ""
    owner: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class LessonAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    category: LessonCategory = LessonCategory.PROCESS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class LessonReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    implementation_rate: float = 0.0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_recurrence: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    recurring_issues: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class LessonsLearnedAnalyticsEngine:
    """Track lessons learned and recurrence."""

    def __init__(
        self,
        max_records: int = 200000,
        impl_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = impl_threshold
        self._records: list[LessonRecord] = []
        self._analyses: list[LessonAnalysis] = []
        logger.info(
            "lessons_learned.initialized",
            max_records=max_records,
        )

    def add_record(
        self,
        incident_id: str,
        category: LessonCategory = (LessonCategory.PROCESS),
        recurrence: RecurrenceRate = (RecurrenceRate.NONE),
        status: ImplementationStatus = (ImplementationStatus.PROPOSED),
        lesson_text: str = "",
        action_item: str = "",
        owner: str = "",
        service: str = "",
        team: str = "",
    ) -> LessonRecord:
        record = LessonRecord(
            incident_id=incident_id,
            category=category,
            recurrence=recurrence,
            status=status,
            lesson_text=lesson_text,
            action_item=action_item,
            owner=owner,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "lessons_learned.record_added",
            record_id=record.id,
            category=category.value,
        )
        return record

    def get_record(self, record_id: str) -> LessonRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        category: LessonCategory | None = None,
        status: ImplementationStatus | None = None,
        limit: int = 50,
    ) -> list[LessonRecord]:
        results = list(self._records)
        if category is not None:
            results = [r for r in results if r.category == category]
        if status is not None:
            results = [r for r in results if r.status == status]
        return results[-limit:]

    # -- domain operations ---

    def track_lessons(
        self,
    ) -> list[dict[str, Any]]:
        """Track lessons by category."""
        cat_data: dict[str, list[LessonRecord]] = {}
        for r in self._records:
            cat_data.setdefault(r.category.value, []).append(r)
        results: list[dict[str, Any]] = []
        for cat, records in cat_data.items():
            done = sum(1 for r in records if r.status == ImplementationStatus.COMPLETED)
            rate = round(done / len(records) * 100, 2) if records else 0.0
            results.append(
                {
                    "category": cat,
                    "total": len(records),
                    "completed": done,
                    "impl_rate": rate,
                }
            )
        return sorted(
            results,
            key=lambda x: x["impl_rate"],
        )

    def measure_implementation(
        self,
    ) -> list[dict[str, Any]]:
        """Measure implementation by status."""
        st_data: dict[str, list[LessonRecord]] = {}
        for r in self._records:
            st_data.setdefault(r.status.value, []).append(r)
        results: list[dict[str, Any]] = []
        for st, records in st_data.items():
            results.append(
                {
                    "status": st,
                    "count": len(records),
                    "pct": round(
                        len(records) / max(len(self._records), 1) * 100,
                        2,
                    ),
                }
            )
        return sorted(
            results,
            key=lambda x: x["count"],
            reverse=True,
        )

    def detect_recurring_issues(
        self,
    ) -> list[dict[str, Any]]:
        """Detect recurring issues."""
        recurring = [
            r
            for r in self._records
            if r.recurrence
            in (
                RecurrenceRate.FREQUENT,
                RecurrenceRate.CHRONIC,
            )
        ]
        cat_data: dict[str, list[LessonRecord]] = {}
        for r in recurring:
            cat_data.setdefault(r.category.value, []).append(r)
        results: list[dict[str, Any]] = []
        for cat, records in cat_data.items():
            unresolved = sum(1 for r in records if r.status != ImplementationStatus.COMPLETED)
            results.append(
                {
                    "category": cat,
                    "recurring_count": len(records),
                    "unresolved": unresolved,
                    "severity": "critical"
                    if unresolved > 5
                    else "high"
                    if unresolved > 2
                    else "medium",
                }
            )
        return sorted(
            results,
            key=lambda x: x["recurring_count"],
            reverse=True,
        )

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.incident_id == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        done = sum(1 for r in matched if r.status == ImplementationStatus.COMPLETED)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "completed": done,
        }

    def generate_report(self) -> LessonReport:
        by_c: dict[str, int] = {}
        by_r: dict[str, int] = {}
        by_s: dict[str, int] = {}
        for r in self._records:
            by_c[r.category.value] = by_c.get(r.category.value, 0) + 1
            by_r[r.recurrence.value] = by_r.get(r.recurrence.value, 0) + 1
            by_s[r.status.value] = by_s.get(r.status.value, 0) + 1
        done = sum(1 for r in self._records if r.status == ImplementationStatus.COMPLETED)
        rate = round(done / len(self._records) * 100, 2) if self._records else 0.0
        recurring = [
            r.category.value
            for r in self._records
            if r.recurrence
            in (
                RecurrenceRate.FREQUENT,
                RecurrenceRate.CHRONIC,
            )
        ]
        recs: list[str] = []
        if rate < self._threshold:
            recs.append(f"Impl rate {rate}% below {self._threshold}%")
        if recurring:
            recs.append(f"{len(recurring)} recurring issues")
        if not recs:
            recs.append("Lessons Learned Analytics healthy")
        return LessonReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            implementation_rate=rate,
            by_category=by_c,
            by_recurrence=by_r,
            by_status=by_s,
            recurring_issues=list(set(recurring)),
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("lessons_learned.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        c_dist: dict[str, int] = {}
        for r in self._records:
            k = r.category.value
            c_dist[k] = c_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "impl_threshold": self._threshold,
            "category_distribution": c_dist,
            "unique_incidents": len({r.incident_id for r in self._records}),
        }
