"""ScorecardHistoryEngine -- track scorecard history."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ScorePeriod(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"


class ScoreComponent(StrEnum):
    DETECTION = "detection"
    PREVENTION = "prevention"
    RESPONSE = "response"
    COMPLIANCE = "compliance"
    RISK = "risk"


class DeltaDirection(StrEnum):
    UP = "up"
    DOWN = "down"
    FLAT = "flat"


# --- Models ---


class ScorecardHistoryRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    period: ScorePeriod = ScorePeriod.WEEKLY
    component: ScoreComponent = ScoreComponent.DETECTION
    delta: DeltaDirection = DeltaDirection.FLAT
    score: float = 0.0
    previous_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ScorecardHistoryAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    period: ScorePeriod = ScorePeriod.WEEKLY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ScorecardHistoryReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_period: dict[str, int] = Field(default_factory=dict)
    by_component: dict[str, int] = Field(default_factory=dict)
    by_delta: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ScorecardHistoryEngine:
    """Track scorecard history and trends."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[ScorecardHistoryRecord] = []
        self._analyses: list[ScorecardHistoryAnalysis] = []
        logger.info(
            "scorecard_history_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def record_item(
        self,
        name: str,
        period: ScorePeriod = ScorePeriod.WEEKLY,
        component: ScoreComponent = ScoreComponent.DETECTION,
        delta: DeltaDirection = DeltaDirection.FLAT,
        score: float = 0.0,
        previous_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ScorecardHistoryRecord:
        record = ScorecardHistoryRecord(
            name=name,
            period=period,
            component=component,
            delta=delta,
            score=score,
            previous_score=previous_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "scorecard_history.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> ScorecardHistoryRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        period: ScorePeriod | None = None,
        component: ScoreComponent | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ScorecardHistoryRecord]:
        results = list(self._records)
        if period is not None:
            results = [r for r in results if r.period == period]
        if component is not None:
            results = [r for r in results if r.component == component]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        period: ScorePeriod = ScorePeriod.WEEKLY,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ScorecardHistoryAnalysis:
        analysis = ScorecardHistoryAnalysis(
            name=name,
            period=period,
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

    def record_score(
        self,
    ) -> list[dict[str, Any]]:
        """Record scores by component."""
        comp_data: dict[str, list[ScorecardHistoryRecord]] = {}
        for r in self._records:
            comp_data.setdefault(r.component.value, []).append(r)
        results: list[dict[str, Any]] = []
        for comp, records in comp_data.items():
            scores = [r.score for r in records]
            avg = round(sum(scores) / len(scores), 2)
            latest = records[-1]
            results.append(
                {
                    "component": comp,
                    "avg_score": avg,
                    "latest_score": latest.score,
                    "delta": latest.delta.value,
                    "count": len(records),
                }
            )
        return sorted(results, key=lambda x: x["avg_score"])

    def calculate_delta(
        self,
    ) -> list[dict[str, Any]]:
        """Calculate score deltas."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            change = r.score - r.previous_score
            results.append(
                {
                    "name": r.name,
                    "score": r.score,
                    "previous": r.previous_score,
                    "change": round(change, 2),
                    "direction": r.delta.value,
                    "component": r.component.value,
                }
            )
        return sorted(
            results,
            key=lambda x: abs(x["change"]),
            reverse=True,
        )

    def generate_sparkline_data(
        self,
    ) -> dict[str, Any]:
        """Generate sparkline data per component."""
        comp_data: dict[str, list[float]] = {}
        for r in self._records:
            comp_data.setdefault(r.component.value, []).append(r.score)
        result: dict[str, Any] = {}
        for comp, scores in comp_data.items():
            # Keep last 12 data points
            points = scores[-12:]
            result[comp] = {
                "points": [round(s, 1) for s in points],
                "min": round(min(points), 1),
                "max": round(max(points), 1),
                "latest": round(points[-1], 1),
            }
        return result

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
                        "component": r.component.value,
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
    ) -> ScorecardHistoryReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            v1 = r.period.value
            by_e1[v1] = by_e1.get(v1, 0) + 1
            v2 = r.component.value
            by_e2[v2] = by_e2.get(v2, 0) + 1
            v3 = r.delta.value
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
            recs.append("Scorecard History Engine healthy")
        return ScorecardHistoryReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_period=by_e1,
            by_component=by_e2,
            by_delta=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("scorecard_history_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.period.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "period_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
