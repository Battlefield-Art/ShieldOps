"""ContinuousImprovementEngine — Track continuous improvement cycles across the agent fleet."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ImprovementArea(StrEnum):
    ACCURACY = "accuracy"
    SPEED = "speed"
    COST = "cost"
    COVERAGE = "coverage"
    RELIABILITY = "reliability"


class CyclePhase(StrEnum):
    MEASURE = "measure"
    ANALYZE = "analyze"
    IMPROVE = "improve"
    CONTROL = "control"


class ImprovementStatus(StrEnum):
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    STALLED = "stalled"
    REGRESSED = "regressed"


# --- Models ---


class ContinuousImprovementRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    improvement_area: ImprovementArea = ImprovementArea.ACCURACY
    cycle_phase: CyclePhase = CyclePhase.MEASURE
    improvement_status: ImprovementStatus = ImprovementStatus.IN_PROGRESS
    score: float = 0.0
    baseline_value: float = 0.0
    current_value: float = 0.0
    target_value: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ContinuousImprovementAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    improvement_area: ImprovementArea = ImprovementArea.ACCURACY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ContinuousImprovementReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_improvement_area: dict[str, int] = Field(default_factory=dict)
    by_cycle_phase: dict[str, int] = Field(default_factory=dict)
    by_improvement_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ContinuousImprovementEngine:
    """Track continuous improvement cycles across the agent fleet engine."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[ContinuousImprovementRecord] = []
        self._analyses: list[ContinuousImprovementAnalysis] = []
        logger.info(
            "continuous_improvement_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        improvement_area: ImprovementArea = ImprovementArea.ACCURACY,
        cycle_phase: CyclePhase = CyclePhase.MEASURE,
        improvement_status: ImprovementStatus = ImprovementStatus.IN_PROGRESS,
        score: float = 0.0,
        baseline_value: float = 0.0,
        current_value: float = 0.0,
        target_value: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ContinuousImprovementRecord:
        record = ContinuousImprovementRecord(
            name=name,
            improvement_area=improvement_area,
            cycle_phase=cycle_phase,
            improvement_status=improvement_status,
            score=score,
            baseline_value=baseline_value,
            current_value=current_value,
            target_value=target_value,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "continuous_improvement_engine.record_added",
            record_id=record.id,
            name=name,
            improvement_area=improvement_area.value,
            cycle_phase=cycle_phase.value,
        )
        return record

    def get_record(self, record_id: str) -> ContinuousImprovementRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        improvement_area: ImprovementArea | None = None,
        improvement_status: ImprovementStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ContinuousImprovementRecord]:
        results = list(self._records)
        if improvement_area is not None:
            results = [r for r in results if r.improvement_area == improvement_area]
        if improvement_status is not None:
            results = [r for r in results if r.improvement_status == improvement_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        improvement_area: ImprovementArea = ImprovementArea.ACCURACY,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ContinuousImprovementAnalysis:
        analysis = ContinuousImprovementAnalysis(
            name=name,
            improvement_area=improvement_area,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "continuous_improvement_engine.analysis_added",
            name=name,
            improvement_area=improvement_area.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def measure_improvement_velocity(self) -> list[dict[str, Any]]:
        """Measure the velocity of improvement per area."""
        area_data: dict[str, list[ContinuousImprovementRecord]] = {}
        for r in self._records:
            area_data.setdefault(r.improvement_area.value, []).append(r)
        results: list[dict[str, Any]] = []
        for area, records in area_data.items():
            completed = sum(
                1 for r in records if r.improvement_status == ImprovementStatus.COMPLETED
            )
            total = len(records)
            completion_rate = round(completed / total, 4) if total > 0 else 0.0
            avg_progress: list[float] = []
            for r in records:
                if r.target_value != r.baseline_value:
                    progress = (r.current_value - r.baseline_value) / (
                        r.target_value - r.baseline_value
                    )
                    avg_progress.append(min(max(progress, 0.0), 1.0))
            velocity = round(sum(avg_progress) / len(avg_progress), 4) if avg_progress else 0.0
            results.append(
                {
                    "improvement_area": area,
                    "total_cycles": total,
                    "completed": completed,
                    "completion_rate": completion_rate,
                    "avg_velocity": velocity,
                }
            )
        return sorted(results, key=lambda x: x["avg_velocity"], reverse=True)

    def identify_stalled_improvements(self) -> list[dict[str, Any]]:
        """Identify improvement cycles that have stalled."""
        stalled: list[dict[str, Any]] = []
        for r in self._records:
            if r.improvement_status == ImprovementStatus.STALLED:
                progress = 0.0
                if r.target_value != r.baseline_value:
                    progress = round(
                        (r.current_value - r.baseline_value) / (r.target_value - r.baseline_value),
                        4,
                    )
                stalled.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "team": r.team,
                        "improvement_area": r.improvement_area.value,
                        "cycle_phase": r.cycle_phase.value,
                        "progress": progress,
                        "current_value": r.current_value,
                        "target_value": r.target_value,
                    }
                )
        return sorted(stalled, key=lambda x: x["progress"])

    def recommend_next_improvement(self) -> list[dict[str, Any]]:
        """Recommend the next improvement to focus on per service."""
        svc_data: dict[str, list[ContinuousImprovementRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        recommendations: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            regressed = [r for r in records if r.improvement_status == ImprovementStatus.REGRESSED]
            stalled = [r for r in records if r.improvement_status == ImprovementStatus.STALLED]
            in_progress = [
                r for r in records if r.improvement_status == ImprovementStatus.IN_PROGRESS
            ]
            if regressed:
                target = regressed[0]
                recommendations.append(
                    {
                        "service": svc,
                        "priority": "critical",
                        "focus_area": target.improvement_area.value,
                        "reason": "regression_detected",
                        "suggestion": (
                            f"Address regression in {target.improvement_area.value} for {svc}"
                        ),
                    }
                )
            elif stalled:
                target = stalled[0]
                recommendations.append(
                    {
                        "service": svc,
                        "priority": "high",
                        "focus_area": target.improvement_area.value,
                        "reason": "stalled_improvement",
                        "suggestion": (
                            f"Unblock stalled {target.improvement_area.value} improvement for {svc}"
                        ),
                    }
                )
            elif in_progress:
                target = in_progress[0]
                recommendations.append(
                    {
                        "service": svc,
                        "priority": "medium",
                        "focus_area": target.improvement_area.value,
                        "reason": "continue_progress",
                        "suggestion": (
                            f"Continue {target.improvement_area.value} improvement for {svc}"
                        ),
                    }
                )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "critical" else 1 if x["priority"] == "high" else 2,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.improvement_area.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "improvement_area": r.improvement_area.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> ContinuousImprovementReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.improvement_area.value] = by_e1.get(r.improvement_area.value, 0) + 1
            by_e2[r.cycle_phase.value] = by_e2.get(r.cycle_phase.value, 0) + 1
            by_e3[r.improvement_status.value] = by_e3.get(r.improvement_status.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Continuous Improvement Engine is healthy")
        return ContinuousImprovementReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_improvement_area=by_e1,
            by_cycle_phase=by_e2,
            by_improvement_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("continuous_improvement_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.improvement_area.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "improvement_area_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
