"""CoverageGapTracker -- track coverage gaps."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class GapCategory(StrEnum):
    DETECTION = "detection"
    PREVENTION = "prevention"
    RESPONSE = "response"
    VISIBILITY = "visibility"
    COMPLIANCE = "compliance"


class PriorityLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ClosureRate(StrEnum):
    ON_TRACK = "on_track"
    AT_RISK = "at_risk"
    OVERDUE = "overdue"
    CLOSED = "closed"


# --- Models ---


class CoverageGapRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: GapCategory = GapCategory.DETECTION
    priority: PriorityLevel = PriorityLevel.LOW
    closure: ClosureRate = ClosureRate.ON_TRACK
    score: float = 0.0
    owner: str = ""
    target_date: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CoverageGapAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: GapCategory = GapCategory.DETECTION
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CoverageGapReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_priority: dict[str, int] = Field(default_factory=dict)
    by_closure: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CoverageGapTracker:
    """Track and manage coverage gaps."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[CoverageGapRecord] = []
        self._analyses: list[CoverageGapAnalysis] = []
        logger.info(
            "coverage_gap_tracker.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def record_item(
        self,
        name: str,
        category: GapCategory = GapCategory.DETECTION,
        priority: PriorityLevel = PriorityLevel.LOW,
        closure: ClosureRate = ClosureRate.ON_TRACK,
        score: float = 0.0,
        owner: str = "",
        target_date: str = "",
        service: str = "",
        team: str = "",
    ) -> CoverageGapRecord:
        record = CoverageGapRecord(
            name=name,
            category=category,
            priority=priority,
            closure=closure,
            score=score,
            owner=owner,
            target_date=target_date,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "coverage_gap_tracker.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> CoverageGapRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        category: GapCategory | None = None,
        priority: PriorityLevel | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CoverageGapRecord]:
        results = list(self._records)
        if category is not None:
            results = [r for r in results if r.category == category]
        if priority is not None:
            results = [r for r in results if r.priority == priority]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        category: GapCategory = GapCategory.DETECTION,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CoverageGapAnalysis:
        analysis = CoverageGapAnalysis(
            name=name,
            category=category,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ---

    def track_gap(self) -> list[dict[str, Any]]:
        """Track gaps by category."""
        cat_data: dict[str, list[CoverageGapRecord]] = {}
        for r in self._records:
            cat_data.setdefault(r.category.value, []).append(r)
        results: list[dict[str, Any]] = []
        for cat, records in cat_data.items():
            open_count = sum(1 for r in records if r.closure != ClosureRate.CLOSED)
            results.append(
                {
                    "category": cat,
                    "total": len(records),
                    "open": open_count,
                    "closed": len(records) - open_count,
                }
            )
        return sorted(
            results,
            key=lambda x: x["open"],
            reverse=True,
        )

    def measure_closure_rate(
        self,
    ) -> dict[str, Any]:
        """Measure gap closure rate."""
        if not self._records:
            return {
                "total": 0,
                "closure_rate": 0.0,
            }
        closed = sum(1 for r in self._records if r.closure == ClosureRate.CLOSED)
        total = len(self._records)
        return {
            "total": total,
            "closed": closed,
            "open": total - closed,
            "closure_rate": round(closed / total * 100, 1),
        }

    def forecast_closure(
        self,
    ) -> list[dict[str, Any]]:
        """Forecast closure by priority."""
        pri_data: dict[str, list[CoverageGapRecord]] = {}
        for r in self._records:
            pri_data.setdefault(r.priority.value, []).append(r)
        results: list[dict[str, Any]] = []
        for pri, records in pri_data.items():
            open_gaps = [r for r in records if r.closure != ClosureRate.CLOSED]
            overdue = sum(1 for r in open_gaps if r.closure == ClosureRate.OVERDUE)
            results.append(
                {
                    "priority": pri,
                    "open": len(open_gaps),
                    "overdue": overdue,
                    "on_track": len(open_gaps) - overdue,
                }
            )
        return sorted(
            results,
            key=lambda x: x["overdue"],
            reverse=True,
        )

    # -- standard methods ---

    def identify_gaps(
        self,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "category": r.category.value,
                        "score": r.score,
                        "service": r.service,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

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
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    def generate_report(
        self,
    ) -> CoverageGapReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            v1 = r.category.value
            by_e1[v1] = by_e1.get(v1, 0) + 1
            v2 = r.priority.value
            by_e2[v2] = by_e2.get(v2, 0) + 1
            v3 = r.closure.value
            by_e3[v3] = by_e3.get(v3, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Coverage Gap Tracker is healthy")
        return CoverageGapReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_category=by_e1,
            by_priority=by_e2,
            by_closure=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("coverage_gap_tracker.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.category.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "category_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
